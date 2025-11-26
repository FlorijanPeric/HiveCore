package upr.famnit.managers.connections;

import com.google.gson.*;
import upr.famnit.authentication.*;
import upr.famnit.components.*;
import upr.famnit.managers.DatabaseManager;
import upr.famnit.managers.Overseer;
import upr.famnit.util.LogLevel;
import upr.famnit.util.Logger;
import upr.famnit.util.StreamUtil;

import javax.xml.crypto.Data;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.*;

/**
 * The {@code ProxyManager} class handles management requests from administrative clients,
 * providing functionalities such as key management, monitoring worker connections,
 * retrieving worker statuses, and managing the request queue.
 *
 * <p>This class implements {@link Runnable} and is intended to be executed by a thread pool,
 * allowing concurrent handling of multiple management requests. It authenticates incoming
 * requests, processes various administrative routes, and interacts with the database and
 * worker nodes as necessary.</p>
 *
 * <p>Thread safety is maintained through careful synchronization where needed, and all
 * interactions with shared resources are handled securely and efficiently. The class
 * ensures that unauthorized access is prevented by validating authentication tokens.</p>
 *
 * <p>Instances of {@code ProxyManager} are responsible for managing a single client connection,
 * handling its requests from authentication through to the termination of the connection.</p>
 *
 * @see Runnable
 * @see ClientRequest
 * @see Connection
 * @see DatabaseManager
 * @see Overseer
 */
public class Management implements Runnable {

    /**
     * The {@link Socket} representing the connection to the management client.
     */
    private final Socket clientSocket;

    /**
     * The {@link ClientRequest} object encapsulating the client's request data.
     */
    private ClientRequest clientRequest;

    /**
     * Constructs a new {@code ProxyManager} instance to handle requests from the specified client socket.
     *
     * <p>This constructor initializes the {@link Socket} and prepares the manager to process incoming
     * management requests.</p>
     *
     * @param clientSocket the {@link Socket} connected to the management client
     */
    public Management(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    /**
     * The main execution method for handling management requests.
     *
     * <p>This method performs the following actions:
     * <ol>
     *     <li>Sets the thread name to "Proxy Manager" for easier identification in logs.</li>
     *     <li>Initializes the {@link ClientRequest} by reading the incoming request from the client socket.</li>
     *     <li>Authenticates the client request to ensure it has administrative privileges.</li>
     *     <li>Routes the request to the appropriate handler based on the request URI and method.</li>
     *     <li>Handles any exceptions that occur during request processing and logs relevant information.</li>
     * </ol>
     * </p>
     *
     * <p>Upon successful handling of the request, it logs a success message. If an error occurs,
     * it logs the error and terminates the connection.</p>
     */
    @Override
    public void run() {
        Thread.currentThread().setName("Proxy Manager");
        try {
            clientRequest = new ClientRequest(clientSocket);
        } catch (IOException e) {
            Logger.error("Error reading management request: " + e.getMessage());
            return;
        }

        try {
            if (!isAdminRequest()) {
                respond(ResponseFactory.Unauthorized());
                return;
            }

            switch (clientRequest.getRequest().getUri()) {
                case "/key" -> handleKeyRoute();
                case "/worker/connections" -> handleWorkerConnectionsRoute();
                case "/worker/status" -> handleWorkerStatusRoute();
                case "/worker/pings" -> handleWorkerPingsRoute();
                case "/worker/tags" -> handleWorkerTagsRoute();
                case "/worker/versions" -> handleWorkerHiveVersionRoute();
                case "/worker/command" -> handleWorkerCommandRoute();
                case "/queue" -> handleQueueRoute();
                case "/block" -> handleWorkerBlockRoute();
                case null, default -> respond(ResponseFactory.NotFound());
            }

        } catch (IOException e) {
            Logger.error("Error handling proxy management request: " + e.getMessage());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        Logger.success("Management request finished");
    }


    /**
     * Handles requests to the "/queue" route, managing operations related to the request queue.
     *
     * <p>This method delegates the handling based on the HTTP method of the request.</p>
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleQueueRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleGetQueueLengthRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    /**
     * Handles requests to the "/key" route, managing operations related to authentication keys.
     *
     * <p>This method delegates the handling based on the HTTP method of the request.</p>
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleKeyRoute() throws IOException, SQLException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleListKeysRequest();
            case "POST" -> handleInsertKeyRequest();
            case "DELETE" -> handleDeleteKeyRequest();
            case "PATCH" -> handleKeyChangeReq();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    /**
     * Handles requests to the "/worker/connections" route, providing information about active worker connections.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkerConnectionsRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleActiveWorkersConnectionRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    /**
     * Handles requests to the "/worker/status" route, providing status information about active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkerStatusRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleActiveWorkersStatusRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    /**
     * Handles requests to the "/worker/pings" route, providing the last ping times of active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkerPingsRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleActiveWorkersPingsRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    /**
     * Handles requests to the "/worker/tags" route, providing the tags (models) supported by active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkerTagsRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleActiveWorkersTagsRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    private void handleWorkerBlockRoute() throws IOException, SQLException {
        switch (clientRequest.getRequest().getMethod()){
            case "GET" -> getAllBlock();
            case "POST"-> insertModelBlock();
            case "DELETE"-> deleteModelBlock();
        }
    }

    private void deleteModelBlock() throws IOException, SQLException {

        String authHeader = clientRequest.getRequest().getHeader("Authorization");

        // Validate Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            respond(ResponseFactory.BadRequest());
            return;
        }

        String token = authHeader.substring("Bearer ".length()).trim();

        Key requester = DatabaseManager.getKeyByValue(token);

        if (requester == null) {
            respond(ResponseFactory.MethodNotAllowed());
            return;
        }
        if(!isAdminRequest()){
            respond(ResponseFactory.BadRequest());
            Logger.log("Only admin can Delete allowed models");
            return;
        }
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);
        JsonObject jsonObject = null;
        if (!body.isEmpty()) {
            jsonObject = JsonParser.parseString(body).getAsJsonObject();
        }try {
            if(jsonObject.has("targetKeyValue")){
                String targetKeyValue=jsonObject.get("targetKeyValue").getAsString();
                Key targetKey=DatabaseManager.getKeyByValue(String.valueOf(targetKeyValue));
                if(jsonObject.has("blockedModels")&&jsonObject.get("blockedModels").isJsonNull()){
                    respond(ResponseFactory.BadRequest());
                    Logger.log("No models to delete from table",LogLevel.error);
                    return;
                }
                String allowedModelStr=jsonObject.get("blockedModels").getAsString();
                ArrayList<String> targetModelList = new ArrayList<>(Arrays.asList(allowedModelStr.split(",")));
                for (String model:targetModelList){
                    boolean allowed=DatabaseManager.canKeyUseModel(targetKeyValue,model);
                    if(!allowed){
                        DatabaseManager.blockModelForKey(targetKeyValue,model);
                        continue;
                    }
                    Logger.log("Skipping this model, Model is already allowed",LogLevel.info);
                }
            }

        } catch (SQLException | IOException e) {
            e.printStackTrace();
            Logger.log("There was something wrong with getting the data from the database");
        }


    }

    private void insertModelBlock() throws IOException, SQLException {
        String authHeader = clientRequest.getRequest().getHeader("Authorization");

        // Validate Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            respond(ResponseFactory.BadRequest());
            return;
        }

        String token = authHeader.substring("Bearer ".length()).trim();

        // Get the key from the token
        Key requester = DatabaseManager.getKeyByValue(token);

        if (requester == null) {
            respond(ResponseFactory.MethodNotAllowed());
            return;
        }
        if(!isAdminRequest()){
            respond(ResponseFactory.BadRequest());
            Logger.log("Only admin can insert allowed models");
            return;
        }
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);
        JsonObject jsonObject = null;
        if (!body.isEmpty()) {
            jsonObject = JsonParser.parseString(body).getAsJsonObject();
        }try {

            if(jsonObject != null&&jsonObject.has("targetKeyValue")){
                String targetKeyValue=jsonObject.get("targetKeyValue").getAsString();
                //Key targetKey=DatabaseManager.getKeyByValue(targetKeyValue);
                if(!jsonObject.has("blockedModels")&&jsonObject.get("blockedModels").isJsonNull()){
                    respond(ResponseFactory.BadRequest());
                    Logger.log("No models to add to table",LogLevel.error);
                    return;
                }
                String allowedModelStr=jsonObject.get("blockedModels").getAsString();
                ArrayList<String> targetModelList = new ArrayList<>(Arrays.asList(allowedModelStr.split(",")));
                for (String model:targetModelList){
                  DatabaseManager.blockModelForKey(targetKeyValue,model);
                }
                JsonObject responseJson=new JsonObject();
                responseJson.add("allowedModels",jsonObject);
                byte[] responseBytes=responseJson.toString().getBytes(StandardCharsets.UTF_8);
                respond(ResponseFactory.Ok(responseBytes));
            }
            respond(ResponseFactory.Ok());
        } catch (SQLException e) {
            e.printStackTrace();
            Logger.log("There was something wrong with getting the data from the database");
        }

    }

    private void getAllBlock() throws IOException,SQLException {
        String authHeader = clientRequest.getRequest().getHeader("Authorization");

        // Validate Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            respond(ResponseFactory.BadRequest());
            return;
        }

        String token = authHeader.substring("Bearer ".length()).trim();

        // Get the key from the token
        Key requester = DatabaseManager.getKeyByValue(token);

        if (requester == null) {
            respond(ResponseFactory.MethodNotAllowed());
            return;
        }
        boolean isAdmin = isAdminRequest();
        Key targetKey;
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);
        JsonObject jsonObject = null;
        if (!body.isEmpty()) {
            jsonObject = JsonParser.parseString(body).getAsJsonObject();
        }

        try {
            if(jsonObject.has("targetKeyValue")){
                String targetKeyValue=jsonObject.get("targetKeyValue").getAsString();
                if(!targetKeyValue.equals(token)&&requester.getRole()!=Role.Admin){
                    respond(ResponseFactory.MethodNotAllowed());
                    Logger.log("Unauthorized attempt to view another key's blocked models", LogLevel.warn);
                    Logger.log("Admin can view all, others cannot");
                    return;
                }
                //Check target key de se prepričam de obstaja
                targetKey=DatabaseManager.getKeyByValue(targetKeyValue);
                if (targetKey==null){
                    respond(ResponseFactory.BadRequest());
                    Logger.log("Target key not found: "+targetKeyValue,LogLevel.error);
                    return;
                }
                //Nucam ArrayList de lažje loopam skoz object pa tud za response generation
                ArrayList<String>allowedModels=getAllowed(targetKeyValue);
                JsonArray responseArray=new JsonArray();
                for(String model:allowedModels){
                    responseArray.add(model);
                }
                JsonObject responseJson=new JsonObject();
                responseJson.add("blockedModels",responseArray);
                byte[] responseBytes=responseJson.toString().getBytes(StandardCharsets.UTF_8);
                respond(ResponseFactory.Ok(responseBytes));
                Logger.log("Retrieved: "+allowedModels.size() + " blocked models for key " + requester.getName(), LogLevel.info);
            }
        }catch (SQLException e){
            e.printStackTrace();
            respond(ResponseFactory.InternalServerError());
        }
    }

    /**
     * Handles requests to the "/worker/version/hive" route, providing the Hive versions of active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkerHiveVersionRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "GET" -> handleWorkersHiveVersionRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    private void handleWorkerCommandRoute() throws IOException {
        switch (clientRequest.getRequest().getMethod()) {
            case "POST" -> handleWorkersCommandRequest();
            case null, default -> respond(ResponseFactory.NotFound());
        }
    }

    private void handleWorkersCommandRequest() throws IOException {
        Gson gson = new GsonBuilder().create();
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);
        WorkerCommand workerCommand = gson.fromJson(body, WorkerCommand.class);
        Logger.info("Recieved worker (" + workerCommand.worker + ") command: " + workerCommand.command);
        Response response = Overseer.sendCommand(workerCommand, clientSocket);
        // something wrong.
        if (response != null) {
            respond(response);
        }
    }

    /**
     * Handles GET requests to retrieve the current length of the request queue.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleGetQueueLengthRequest() throws IOException {
        HashMap<String, Integer> queueLengths = RequestQue.getQueLengths();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(queueLengths);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles GET requests to retrieve information about active worker connections.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleActiveWorkersConnectionRequest() throws IOException {
        TreeMap<String, Integer> activeConnections = Overseer.getActiveConnections();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(activeConnections);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles GET requests to retrieve the verification statuses of active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleActiveWorkersStatusRequest() throws IOException {
        TreeMap<String, ArrayList<VerificationStatus>> activeStatuses = Overseer.getConnectionsStatus();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(activeStatuses);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles GET requests to retrieve the last ping times of active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleActiveWorkersPingsRequest() throws IOException {
        TreeMap<String, ArrayList<String>> lastPings = Overseer.getLastPings();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(lastPings);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles GET requests to retrieve the tags (models) supported by active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleActiveWorkersTagsRequest() throws IOException {
        TreeMap<String, Set<String>> tags = Overseer.getTags();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(tags);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles GET requests to retrieve the Hive and Ollama versions of active workers.
     *
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void handleWorkersHiveVersionRequest() throws IOException {
        TreeMap<String, WorkerVersion> hiveVersions = Overseer.getNodeVersions();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(hiveVersions);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }


    /**
     * Handles POST requests to insert a new authentication key into the system.
     *
     * <p>This method performs the following actions:
     * <ol>
     *     <li>Parses the incoming JSON body to create a {@link SubmittedKey} object.</li>
     *     <li>Converts the submitted key into a {@link Key} object.</li>
     *     <li>Inserts the new key into the database using {@link DatabaseManager}.</li>
     *     <li>Sends a successful response containing the key's value.</li>
     * </ol>
     * </p>
     *
     * @throws IOException if an I/O error occurs during request processing or response transmission
     */
    private void handleInsertKeyRequest() throws IOException {
        Gson gson = new GsonBuilder().create();
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);
        SubmittedKey submittedKey = gson.fromJson(body, SubmittedKey.class);
        Key validKey = new Key(submittedKey);

        try {
            DatabaseManager.insertKey(validKey);
        } catch (SQLException e) {
            Logger.error("Error inserting new key: " + e.getMessage());
            respond(ResponseFactory.BadRequest());
            return;
        }

        respond(ResponseFactory.Ok(validKey.getValue().getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles DELETE requests to delete a authentication key from the system if you are not trying.
     * to delete ADMIN
     * <p>This method performs the following actions:
     * <ol>
     *     <li>Parses the incoming JSON body to create a {@link SubmittedKey} object.</li>
     *     <li>Converts the submitted key into a {@link Key} object.</li>
     *     <li>Deletes the whole record with that key {@link DatabaseManager}.</li>
     *     <li>Sends a successful response containing the key's value.</li>
     * </ol>
     * </p>
     *
     * @throws IOException if an I/O error occurs during request processing or response transmission
     */
    private void handleDeleteKeyRequest() throws IOException, SQLException {
        Gson gson = new GsonBuilder().create();
        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);

        JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();

        String authValue = jsonObject.get("auth").getAsString();
        Key requester = DatabaseManager.getKeyByValue(authValue);

        if (requester == null || (requester.getRole()) != Role.Admin) {
            respond(ResponseFactory.MethodNotAllowed());
            return;
        }

        String value = jsonObject.has("value") ? jsonObject.get("value").getAsString().trim() : "";
        String name = jsonObject.has("name") ? jsonObject.get("name").getAsString().trim() : "";
        Key key = null;
        boolean deleteByValue = false;


        try {
            if (!value.isEmpty()) {
                key = DatabaseManager.getKeyByValue(value);
                deleteByValue = true;
            }
            if (key == null && !name.isEmpty()) {
                key = DatabaseManager.getKeyByName(name);
            }

            if (key != null) {
                if (deleteByValue) {
                    boolean deleted = DatabaseManager.deleteKeyByValue(key.getValue());
                    Logger.log("Key deleted by value: " + key.getValue(), LogLevel.success);
                    respond(ResponseFactory.Ok(value.getBytes()));
                    return;
                } else if (!deleteByValue && key.getRole() != Role.Admin) {
                    // Key exists and is NOT Admin → delete it
                    Logger.log(key.toString());
                    boolean deleted = DatabaseManager.deleteKeyByName(key.getName());

                    if (deleted) {
                        Logger.log("Key deleted: " + key.getName(), LogLevel.success);
                        respond(ResponseFactory.Ok(name.getBytes()));
                        return;

                    }
                }
            }
            respond(ResponseFactory.NotFound());
            Logger.log("Key could not be deleted", LogLevel.error);
        } catch (SQLException e) {
            e.printStackTrace();
            //respond(ResponseFactory.BadRequest());
        }
    }


    /**
     * Handles GET requests to list all authentication keys in the system.
     *
     * <p>This method performs the following actions:
     * <ol>
     *     <li>Retrieves all keys from the database using {@link DatabaseManager}.</li>
     *     <li>Converts the list of keys to JSON format.</li>
     *     <li>Sends the JSON response back to the client.</li>
     * </ol>
     * </p>
     *
     * @throws IOException if an I/O error occurs during request processing or response transmission
     */
    private void handleListKeysRequest() throws IOException {
        ArrayList<Key> keys;
        try {
            keys = DatabaseManager.getAllKeys();
        } catch (SQLException e) {
            Logger.error("Error fetching keys from database: " + e.getMessage());
            respond(ResponseFactory.BadRequest());
            return;
        }

        if (keys == null || keys.isEmpty()) {
            respond(ResponseFactory.NotFound());
            return;
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String body = gson.toJson(keys);
        respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Handles a request to modify an existing key's properties such as its name or role.
     *
     * <p>This method processes an incoming JSON request from the client containing one or more
     * modification instructions. Depending on the provided fields, the method can update a key's:
     * <ul>
     *     <li><strong>role</strong> — via {@code roleNew}</li>
     *     <li><strong>name</strong> — via {@code newName}</li>
     *     <li>or both</li>
     * </ul>
     *
     * <p>The request must include an authentication value ({@code auth}) belonging to a key with
     * {@link Role#Admin} privileges; otherwise, the operation is rejected.</p>
     *
     * <p>Valid update combinations:</p>
     * <ul>
     *     <li>Identify key by authentication value ({@code value})</li>
     *     <li>Identify key by name ({@code name})</li>
     *     <li>Optionally update role, name, or both</li>
     * </ul>
     *
     * <p>Depending on the requested changes, this method delegates updates to the appropriate
     * {@link DatabaseManager} methods, sends an HTTP response via {@link ResponseFactory},
     * and logs the operation outcome.</p>
     *
     * @throws IOException  if reading the request body or writing the response fails
     * @throws SQLException if a database operation triggered by the update fails
     */

    private void handleKeyChangeReq() throws IOException, SQLException {
        String authHeader = clientRequest.getRequest().getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            respond(ResponseFactory.BadRequest());
            return;
        }

        String token = authHeader.substring("Bearer ".length()).trim();

        String body = new String(clientRequest.getRequest().getBody(), StandardCharsets.UTF_8);

        JsonObject jsonObject = JsonParser.parseString(body).getAsJsonObject();

        Key requester = DatabaseManager.getKeyByValue(token);
        boolean update = false;

        if (requester == null || (requester.getRole()) != Role.Admin) {
            respond(ResponseFactory.MethodNotAllowed());
            return;
        }
        String auth = getJsonString(jsonObject, "value");
        String name = getJsonString(jsonObject, "name");
        String newRole = getJsonString(jsonObject, "roleNew");
        String newName = getJsonString(jsonObject, "newName");

        boolean isnewName = !newName.isEmpty();
        boolean hasNewRole = !newRole.isEmpty();
        boolean bothChange = isnewName && hasNewRole;
        try {


            if (!auth.isEmpty() && name.isEmpty()) {

                if (bothChange) {
                    update = DatabaseManager.changeKeyRoleByAuth(auth, Role.fromString(newRole));
                    update = DatabaseManager.changeKeyNameByAuth(auth, newName);
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    Logger.log("Change of name and role succesfull", LogLevel.success);
                    return;
                } else if (isnewName) {
                    update = DatabaseManager.changeKeyNameByAuth(auth,newName);
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    return;

                } else if (hasNewRole) {
                    update = DatabaseManager.changeKeyRoleByAuth(auth, Role.fromString(newRole));
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    return;
                }
                respond(ResponseFactory.BadRequest());
                Logger.log("Cant update", LogLevel.error);

            } else if (!name.isEmpty() && auth.isEmpty()) {
                if (bothChange) {
                    update = DatabaseManager.changeKeyRoleByName(name, Role.fromString(newRole));
                    update = DatabaseManager.changeKeyNameByName(name, newName);
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    Logger.log("Change of name and role succesfull", LogLevel.success);
                    return;
                } else if (isnewName) {
                    update = DatabaseManager.changeKeyNameByName(name,newName);
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    return;

                } else if (hasNewRole) {
                    update = DatabaseManager.changeKeyRoleByName(name, Role.fromString(newRole));
                    respond(ResponseFactory.Ok(body.getBytes(StandardCharsets.UTF_8)));
                    return;
                }
                respond(ResponseFactory.BadRequest());
                Logger.log("Cant update", LogLevel.error);
                return;

            }
        }catch (SQLException e){
            e.printStackTrace();
        }
        if (!update){
            respond(ResponseFactory.BadRequest());
        }
    }

    /**
     * Determines whether the incoming request is from an authenticated administrator.
     *
     * <p>This method checks the "Authorization" header for a valid Bearer token and verifies
     * that the associated key has administrative privileges.</p>
     *
     * @return {@code true} if the request is from an admin; {@code false} otherwise
     */
    private boolean isAdminRequest() {
        Map<String, String> headers = clientRequest.getRequest().getHeaders();
        if (headers == null || headers.isEmpty()) {
            return false;
        }

        String authHeader = headers.get("authorization");

        if (authHeader == null) {
            return false;
        }

        if (!authHeader.startsWith("Bearer ")) {
            return false;
        }

        authHeader = authHeader.replace("Bearer ", "").trim();
        return Role.Admin == KeyUtil.getKeyRole(authHeader);
    }

    /**
     * Sends a response to the client through the client socket's output stream.
     *
     * @param response the {@link Response} object containing the response data
     * @throws IOException if an I/O error occurs during response transmission
     */
    private void respond(Response response) throws IOException {
        StreamUtil.sendResponse(clientRequest.getClientSocket().getOutputStream(), response);
    }
    private String getJsonString(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull()
                ? obj.get(key).getAsString().trim()
                : "";
    }

    private ArrayList<String> getAllowed(String keyId) throws SQLException {
        return DatabaseManager.getBlockedModelsForKey(keyId);
    }


}
