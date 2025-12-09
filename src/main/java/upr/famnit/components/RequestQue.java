package upr.famnit.components;

import upr.famnit.managers.DatabaseManager;
import upr.famnit.util.LogLevel;
import upr.famnit.util.Logger;
import upr.famnit.util.StreamUtil;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

/**
 * The {@code RequestQue} class manages client requests by organizing them into queues
 * based on either model names or node names. It provides functionality to add tasks
 * to the appropriate queues and retrieve tasks for processing.
 */
public class RequestQue {

    /**
     * A concurrent map that holds queues of {@link ClientRequest} objects keyed by model name.
     */
    private static final ConcurrentMap<String, ConcurrentLinkedQueue<ClientRequest>> modelQue = new ConcurrentHashMap<>();

    /**
     * A concurrent map that holds queues of {@link ClientRequest} objects keyed by node name.
     */
    private static final ConcurrentMap<String, ConcurrentLinkedQueue<ClientRequest>> nodeQue = new ConcurrentHashMap<>();

    /**
     * Retrieves a client request task based on the specified model and node names.
     *
     * <p>The method first attempts to fetch a task from the queue associated with the
     * provided node name. If no task is found, it then attempts to retrieve a task
     * from the queue associated with the model name.</p>
     *
     * @param modelName the name of the model associated with the request
     * @param nodeName the name of the node associated with the request
     * @return the next {@link ClientRequest} if available; otherwise, {@code null}
     */
    public static ClientRequest getTask(String modelName, String nodeName) {
        ConcurrentLinkedQueue<ClientRequest> specificNodeQue = nodeQue.get(nodeName);
        if (specificNodeQue != null) {
            ClientRequest request = specificNodeQue.poll();
            if (request != null) {
                request.stampQueueLeave(nodeName);
                return request;
            }
        }

        ConcurrentLinkedQueue<ClientRequest> specificModelQue = modelQue.get(modelName);
        if (specificModelQue != null) {
            ClientRequest request = specificModelQue.poll();
            if (request != null) {
                request.stampQueueLeave(nodeName);
                return request;
            }
        }
        return null;
    }

    public static ClientRequest getNodeTask(String nodeName) {
        ConcurrentLinkedQueue<ClientRequest> specificNodeQue = nodeQue.get(nodeName);
        if (specificNodeQue != null) {
            ClientRequest request = specificNodeQue.poll();
            if (request != null) {
                request.stampQueueLeave(nodeName);
                return request;
            }
        }

        return null;
    }

    public static ClientRequest getModelTask(String modelName, String nodeName) {
        ConcurrentLinkedQueue<ClientRequest> specificModelQue = modelQue.get(modelName);
        if (specificModelQue != null) {
            ClientRequest request = specificModelQue.poll();
            if (request != null) {
                request.stampQueueLeave(nodeName);
                return request;
            }
        }
        return null;
    }

    /**
     * Adds a client request task to the appropriate queue based on its headers.
     *
     * <p>If the request protocol is "HIVE", the task is not added to any queue.
     * If the request contains a "node" header, it is added to the node-specific queue.
     * Otherwise, it is added to the model-specific queue.</p>
     *
     * @param request the {@link ClientRequest} to be added
     * @return {@code true} if the task was successfully added; {@code false} otherwise
     */
    public static boolean addTask(ClientRequest request) throws SQLException {
        if (request.getRequest().getProtocol().equals("HIVE")) {
            return false;
        }
        String model = extractModel(request);
        String token = extractToken(request);
        if(!isAllowedForModel(model,token)){
            Logger.log("Model not allowed for the person", LogLevel.error);
            return false;
        }
        if (request.getRequest().getHeaders().containsKey("node")) {
            return addToQueByNode(request);
        } else {
            return addToQueByModel(request);
        }
    }

    public static boolean addHiveTask(ClientRequest request, String worker) {
        return addToQueByNode(request, worker);
    }

    /**
     * Adds a client request task to the model-specific queue.
     *
     * <p>The method extracts the model name from the request body and adds the
     * request to the corresponding queue. If the model name cannot be determined,
     * a warning is logged and the task is not added.</p>
     *
     * @param request the {@link ClientRequest} to be added
     * @return {@code true} if the task was successfully added; {@code false} otherwise
     */
    private static boolean addToQueByModel(ClientRequest request) {
        request.stampQueueEnter();
        String modelName = StreamUtil.getValueFromJSONBody("model", request.getRequest().getBody());

        if (modelName == null) {
            Logger.warn("Unable to determine target model for request.");
            return false;
        }

        modelQue.computeIfAbsent(modelName, k -> new ConcurrentLinkedQueue<>()).add(request);

        Logger.info("Request for model " + modelName + " added to the queue. (" + request.getClientSocket().getRemoteSocketAddress() + ")");
        return true;
    }

    /**
     * Adds a client request task to the node-specific queue.
     *
     * <p>The method retrieves the node name from the request headers and adds the
     * request to the corresponding queue. If the node name is not specified, a
     * warning is logged and the task is not added.</p>
     *
     * @param request the {@link ClientRequest} to be added
     * @return {@code true} if the task was successfully added; {@code false} otherwise
     */
    private static boolean addToQueByNode(ClientRequest request) {
        request.stampQueueEnter();
        String nodeName = request.getRequest().getHeaders().get("node");

        if (nodeName == null) {
            Logger.warn("Unable to determine target node for request.");
            return false;
        }

        nodeQue.computeIfAbsent(nodeName, k -> new ConcurrentLinkedQueue<>()).add(request);
        Logger.info("Request for worker node " + nodeName + " added to the queue. (" + request.getClientSocket().getRemoteSocketAddress() + ")");
        return true;
    }

    private static boolean addToQueByNode(ClientRequest request, String nodeName) {
        request.stampQueueEnter();

        if (nodeName == null) {
            Logger.warn("Unable to determine target node for request.");
            return false;
        }

        nodeQue.computeIfAbsent(nodeName, k -> new ConcurrentLinkedQueue<>()).add(request);
        Logger.info("Request for worker node " + nodeName + " added to the queue. (" + request.getClientSocket().getRemoteSocketAddress() + ")");
        return true;
    }

    /**
     * Retrieves the lengths of all model and node queues.
     *
     * <p>The method returns a {@link HashMap} where each key is prefixed with
     * "Model: " or "Node: " to indicate the type of queue, and the value is the
     * number of tasks in that queue.</p>
     *
     * @return a {@link HashMap} containing the lengths of each queue
     */
    public static HashMap<String, Integer> getQueLengths() {
        HashMap<String, Integer> queLengths = new HashMap<>();
        modelQue.forEach((model, queue) -> queLengths.put("Model: " + model, queue.size()));
        nodeQue.forEach((node, queue) -> queLengths.put("Node: " + node, queue.size()));
        return queLengths;
    }

    /**
     * Retrieves an unhandleable client request task based on provided node and model names.
     *
     * <p>The method searches for a task in the node queues excluding the specified node names.
     * If no suitable task is found, it searches the model queues excluding the specified model names.
     * The first matching task found is returned.</p>
     *
     * @param nodeNames a list of node names to exclude from the search
     * @param modelNames a set of model names to exclude from the search
     * @return a {@link ClientRequest} if an unhandleable task is found; otherwise, {@code null}
     */
    public static ClientRequest getUnhandlableTask(ArrayList<String> nodeNames, Set<String> modelNames) {
        // Search node queues excluding specified nodes
        for (String nodeName : nodeQue.keySet()) {
            if (nodeNames.contains(nodeName)) {
                continue;
            }

            ConcurrentLinkedQueue<ClientRequest> specificNodeQue = nodeQue.get(nodeName);
            if (specificNodeQue == null) {
                continue;
            }

            ClientRequest req = specificNodeQue.poll();
            if (req != null) {
                return req;
            }
        }

        // Search model queues excluding specified models
        for (String modelName : modelQue.keySet()) {
            if (modelNames.contains(modelName)) {
                continue;
            }

            ConcurrentLinkedQueue<ClientRequest> specificModelQue = modelQue.get(modelName);
            if (specificModelQue == null) {
                continue;
            }

            ClientRequest req = specificModelQue.poll();
            if (req != null) {
                return req;
            }
        }

        return null;
    }
    /**
     * Extracts the model name from the JSON request body.
     *
     * <p>This expects the request body to contain a JSON key named {@code "model"}.
     * If the key is missing or unreadable, {@code null} is returned.</p>
     *
     * @param request the {@link ClientRequest} whose model should be extracted
     * @return the model name, or {@code null} if not found
     */
    public static String extractModel(ClientRequest request) {
        return StreamUtil.getValueFromJSONBody("model", request.getRequest().getBody());
    }

    /**
     * Extracts a Bearer token from the request's {@code Authorization} header.
     *
     * <p>The header must be in the format:</p>
     * <pre>
     * Authorization: Bearer &lt;token&gt;
     * </pre>
     *
     * <p>If the header is missing, malformed, or does not begin with "Bearer ",
     * {@code null} is returned.</p>
     *
     * @param request the {@link ClientRequest} containing the Authorization header
     * @return the extracted token, or {@code null} if not present or invalid
     */
    public static String extractToken(ClientRequest request) {
        String auth = request.getRequest().getHeaders().get("Authorization");
        if (auth == null) return null;
        if (!auth.startsWith("Bearer ")) return null;
        return auth.substring("Bearer ".length()).trim();
    }

    /**
     * Determines whether a given token is allowed to access a specific model.
     *
     * <p>The permission rules are as follows:</p>
     *
     * <ul>
     *     <li><b>Blacklist overrides everything:</b><br>
     *         If the model is in the token's blacklist, access is denied.</li>
     *
     *     <li><b>Whitelist restricts access only when it is non-empty:</b><br>
     *         If the whitelist contains entries, then the model must appear in the
     *         whitelist. If the whitelist is empty, all non-blacklisted models are allowed.</li>
     *
     *     <li><b>If the model is in neither whitelist nor blacklist:</b><br>
     *         It is allowed as long as the whitelist is empty.</li>
     * </ul>
     *
     * <p>This method fetches the allow- and block-lists from the database on each call.</p>
     *
     * @param model the model being requested
     * @param token the client's authentication token
     * @return {@code true} if access is permitted; {@code false} otherwise
     * @throws SQLException if permission data cannot be retrieved
     */
    private static boolean isAllowedForModel(String model, String token) throws SQLException {
        // TODO: call your real permission system
        ArrayList<String> block=DatabaseManager.getBlockedModelsForKey(token);
        ArrayList<String> allow=DatabaseManager.getAllowedModelsForKey(token);
        boolean allowed=true;
        if (block.contains(model)) {
            return false;
        }

        if (!allow.isEmpty() && !allow.contains(model)) {
            return false;
        }

        return true;
    }


}
