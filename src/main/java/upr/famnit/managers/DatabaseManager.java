package upr.famnit.managers;

import upr.famnit.authentication.Key;
import upr.famnit.authentication.Role;
import upr.famnit.util.Logger;

import java.sql.*;
import java.util.ArrayList;

import static upr.famnit.util.Config.DATABASE_URL;

/**
 * The {@code DatabaseManager} class provides utility methods for interacting with the application's SQLite database.
 *
 * <p>This class manages the database connection and offers methods to create necessary tables,
 * insert new keys, retrieve keys by value, and fetch all keys from the database. It ensures that
 * database operations are performed safely and efficiently, handling SQL exceptions and maintaining
 * the integrity of the data.</p>
 *
 * <p>All methods in this class are synchronized to ensure thread safety when accessed by multiple threads
 * concurrently. This is crucial in a multithreaded environment where multiple clients might be interacting
 * with the database simultaneously.</p>
 *
 * <p>The class follows the Singleton pattern for the database connection, ensuring that only one connection
 * instance exists throughout the application's lifecycle. This approach conserves resources and maintains
 * consistent access to the database.</p>
 *
 * @see Key
 * @see Logger
 */
public class DatabaseManager {

    /**
     * The singleton {@link Connection} instance for interacting with the SQLite database.
     */
    private static Connection connection;

    /**
     * Establishes a connection to the SQLite database using the configured database URL.
     *
     * <p>This method follows a singleton pattern: if a connection already exists and is open,
     * it reuses that connection. Otherwise, it creates a new connection to the database.</p>
     *
     * <p>It also configures SQLite to use WAL (Write-Ahead Logging) mode, which allows:
     * <ul>
     *     <li>Concurrent reads and writes without blocking each other.</li>
     *     <li>Faster commits because changes are written to a log instead of directly overwriting the main database.</li>
     *     <li>Reduced chances of hitting SQLITE_BUSY errors when multiple threads access the database.</li>
     * </ul>
     * </p>
     *
     * <p>The {@code busy_timeout} PRAGMA is also set to 2000ms (2 seconds), which tells SQLite
     * to wait up to 2 seconds for a locked database to become available instead of immediately
     * throwing an SQLITE_BUSY exception.</p>
     * <p>The timeout is to avoid SQL DB lockout</p>
     *
     * <p>Overall, this setup is essential for multithreaded applications that share a single
     * SQLite database connection, like your server handling multiple POST requests simultaneously.</p>
     *
     * @return the {@link Connection} object for interacting with the database
     * @throws SQLException if a database access error occurs or the URL is invalid
     */

    public static Connection connect() throws SQLException {
        if (connection == null || connection.isClosed()) {
            connection = DriverManager.getConnection(DATABASE_URL);
            Logger.info("Database connection established.");
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("PRAGMA journal_mode=WAL;");
            stmt.execute("PRAGMA synchronous=NORMAL;");
            stmt.execute("PRAGMA busy_timeout = 2000;");
        }

        Logger.info("Database connection established.");
        return connection;
    }

    /**
     * Creates the {@code keys} table in the database if it does not already exist.
     *
     * <p>The {@code keys} table stores information about authentication keys, including their
     * unique identifier, name, value, and associated role. This method ensures that the
     * table structure is in place before any key-related operations are performed.</p>
     *
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */
    public static synchronized void createKeysTable() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS keys (\n"
                + "     id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + "     name TEXT NOT NULL UNIQUE,\n"
                + "     value TEXT NOT NULL,\n"
                + "     role TEXT NOT NULL\n"
                + ");";

        try (Connection conn = connect(); Statement statement = conn.createStatement()) {
            statement.execute(sql);
            Logger.info("Keys table created or already exists.");
        }
    }

    /**
     * Creates the {@code blocked_models} table in the database if it does not already exist.
     *
     * <p>The {@code blocked_models} table stores model usage restrictions for each key.
     * Each entry links a key (via its {@code key_id}) to a model name that the key is
     * not allowed to access. This allows fine-grained control over which models a user
     * or API key can use.</p>
     *
     * <p>The table uses a composite primary key consisting of {@code key_id} and
     * {@code model_name} to ensure that the same model cannot be blocked twice for the
     * same key. A foreign key constraint references the {@code keys} table, ensuring that
     * restrictions are automatically removed if a key is deleted.</p>
     *
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized void createBlockedModelsTable() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS blocked_models (\n"
                + "     key_value TEXT NOT NULL,\n"
                + "     model_name TEXT NOT NULL,\n"
                + "     PRIMARY KEY (key_value, model_name),\n"
                + "     FOREIGN KEY (key_value) REFERENCES keys(value) ON DELETE CASCADE\n"
                + ");";

        try (Connection conn = connect(); Statement statement = conn.createStatement()) {
            statement.execute(sql);
            Logger.info("Blocked models table created or already exists.");
        }
    }


    /**
     * Inserts a new {@link Key} into the {@code keys} table.
     *
     * <p>This method adds a new key with its name, value, and role to the database. It ensures that
     * the key name is unique to prevent duplicate entries.</p>
     *
     * @param key the {@link Key} object to be inserted into the database
     * @throws SQLException if a database access error occurs, the SQL statement is invalid, or the key name violates uniqueness
     */
    public static synchronized void insertKey(Key key) throws SQLException {
        String sql = "INSERT INTO keys(name, value, role) VALUES(?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, key.getName());
            stmt.setString(2, key.getValue());
            stmt.setString(3, key.getRole().toString());
            stmt.executeUpdate();
            Logger.success("Key inserted successfully: " + key.getName());
        }
    }

    /**
     * Retrieves a {@link Key} from the {@code keys} table based on its value.
     *
     * <p>This method searches for a key with the specified value and returns the corresponding
     * {@link Key} object if found. If no matching key is found, it returns {@code null}.</p>
     *
     * @param value the value of the key to be retrieved
     * @return the {@link Key} object if found; {@code null} otherwise
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */
    public static synchronized Key getKeyByValue(String value) throws SQLException {
        String sql = "SELECT * FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, value);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                Key key = new Key(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("value"),
                        rs.getString("role")
                );
                Logger.info("Key retrieved: " + key.getName());
                return key;
            } else {
                Logger.warn("No key found with value: " + value);
                return null;
            }
        }
    }
    /**
     * Retrieves a {@link Key} from the {@code keys} table based on its Name.
     *
     * <p>This method searches for a key with the specified value and returns the corresponding
     * {@link Key} object if found. If no matching key is found, it returns {@code null}.</p>
     *
     * @param name the value of the key to be retrieved
     * @return the {@link Key} object if found; {@code null} otherwise
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */
    public static synchronized Key getKeyByName(String name) throws SQLException {
        String sql = "SELECT * FROM keys WHERE name = ?";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, name);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                Key key = new Key(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("value"),
                        rs.getString("role")
                );
                Logger.info("Key retrieved: " + key.getName());
                return key;
            } else {
                Logger.warn("No key found with name: " + name);
                return null;
            }
        }
    }

    /**
     * Retrieves all {@link Key} entries from the {@code keys} table.
     *
     * <p>This method fetches all keys stored in the database and returns them as an {@link ArrayList}.
     * It is useful for administrative tasks or for displaying all available keys.</p>
     *
     * @return an {@link ArrayList} containing all {@link Key} objects from the database
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */
    public static synchronized ArrayList<Key> getAllKeys() throws SQLException {
        String sql = "SELECT * FROM keys";
        ArrayList<Key> keys = new ArrayList<>();
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Key key = new Key(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("value"),
                        rs.getString("role")
                );
                keys.add(key);
            }
            Logger.info("Total keys retrieved: " + keys.size());
        }
        return keys;
    }

    /**
     * Deletes a key from the {@code keys} table based on its name.
     *
     * <p>This method attempts to remove a key whose {@code name} matches the specified value.
     * It is commonly used for administrative cleanup operations or key management tasks.</p>
     *
     * @param name the name of the key to delete
     * @return {@code true} if a key with the given name was successfully deleted,
     *         {@code false} if no matching key was found
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean deleteKeyByName(String name) throws SQLException {
        String sql = "DELETE FROM keys WHERE name = ?";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, name);
            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key deleted: " + name);
                return true;
            } else {
                Logger.warn("No key found to delete with name: " + name);
                return false;
            }
        }
    }

    /**
     * Deletes a key from the {@code keys} table based on its value.
     *
     * <p>This method removes a key whose {@code value} field matches the specified authentication
     * token. It is typically used when invalidating or rotating API keys or credentials.</p>
     *
     * @param value the key value (token) to delete
     * @return {@code true} if a key with the given value was deleted, {@code false} otherwise
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean deleteKeyByValue(String value) throws SQLException{
        String sql = "DELETE FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, value);
            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key deleted: " + value);
                return true;
            }

        }
        return false;
    }
    /**
     * Updates the name of a key in the {@code keys} table based on its current name.
     *
     * <p>This method locates a key using its existing {@code name} and updates it to the
     * provided {@code newName}. It is useful for renaming keys in administrative settings.</p>
     *
     * @param oldName the current name of the key to update
     * @param newName the new name to assign to the key
     * @return {@code true} if the key name was successfully updated, {@code false} if no matching key was found
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean changeKeyNameByName(String oldName, String newName) throws SQLException {
        String sql = "UPDATE keys SET name = ? WHERE name = ?";

        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, newName);
            stmt.setString(2, oldName);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key name updated: " + oldName + " → " + newName);
                return true;
            }
        }
        return false;
    }
    /**
     * Updates the role of a key in the {@code keys} table based on its name.
     *
     * <p>This method changes the {@code role} associated with a key identified by its {@code name}.
     * It is often used to modify permissions or access levels dynamically.</p>
     *
     * @param name the name of the key whose role should be updated
     * @param newRole the new {@link Role} to assign to the key
     * @return {@code true} if the role was successfully updated, {@code false} otherwise
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean changeKeyRoleByName(String name, Role newRole) throws SQLException {
        String sql = "UPDATE keys SET role = ? WHERE name = ?";

        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, newRole.toString());
            stmt.setString(2, name);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key role updated: " + name + " → " + newRole);
                return true;
            }
        }
        return false;
    }
    /**
     * Updates the role of a key in the {@code keys} table based on its authentication value.
     *
     * <p>This method locates a key using its {@code value} (typically an authentication token)
     * and assigns it a new {@link Role}. It is useful for adjusting access permissions tied
     * directly to API keys or tokens.</p>
     *
     * @param val the authentication value of the key whose role should be changed
     * @param newRole the new {@link Role} to assign
     * @return {@code true} if the key's role was updated, {@code false} if no matching key was found
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean changeKeyRoleByAuth(String val, Role newRole) throws SQLException {
        String sql = "UPDATE keys SET role = ? WHERE value = ?";

        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, newRole.name());
            stmt.setString(2, val);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key role updated: " + val + " → " + newRole);
                return true;
            }
        }
        return false;
    }

    /**
     * Updates the stored authentication value of a key based on its name.
     *
     * <p>This method identifies a key by its {@code name} and updates the {@code value}
     * field (typically representing the authentication token). It is used when rotating
     * or regenerating key values.</p>
     *
     * @param value the current name of the key to update
     * @param newName the new authentication value to assign to the key
     * @return {@code true} if the key value was successfully updated, {@code false} otherwise
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     */

    public static synchronized boolean changeKeyNameByAuth(String value, String newName) throws SQLException {
        String sql = "UPDATE keys SET value = ? WHERE name = ?";

        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, newName);
            stmt.setString(2, value);

            int affectedRows = stmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Key name updated: " + value + " → " + newName);
                return true;
            }
        }
        return false;
    }
    /**
     * Blocks access to a specific model for the given key in the {@code blocked_models} table.
     *
     * <p>This method first retrieves the key's role from the {@code keys} table. If the key
     * has a role of {@code admin}, the operation is not allowed and an {@link IllegalStateException}
     * is thrown. This ensures that admin keys always retain access to all models.</p>
     *
     * <p>If the key exists and is not an admin, a new entry is inserted into the
     * {@code blocked_models} table linking the {@code key_id} with the {@code model_name}.
     * This effectively prevents the key from using the specified model.</p>
     *
     * <p>Logging is performed at each stage:
     * <ul>
     *     <li>Warnings are logged if the key does not exist or is an admin</li>
     *     <li>Info is logged when a model is successfully blocked for a key</li>
     * </ul></p>
     *
     * @param keyValue      the unique ID of the key in the {@code keys} table
     * @param modelName  the name of the model to block for this key
     *
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     * @throws IllegalStateException if attempting to block a model for an admin key
     */

    public static synchronized void blockModelForKey(String keyValue, String modelName) throws SQLException {
        // First: check the user's role
        String roleSql = "SELECT role FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement roleStmt = conn.prepareStatement(roleSql)) {
            roleStmt.setString(1, keyValue);
            ResultSet rs = roleStmt.executeQuery();

            if (rs.next()) {
                String role = rs.getString("role");

                // Prevent blocking for admin users
                if ("admin".equalsIgnoreCase(role)) {
                    Logger.warn("Attempted to block a model for admin key ID: " + keyValue);
                    throw new IllegalStateException("Admin keys cannot have models blocked.");
                }
            } else {
                Logger.warn("No key found with value: " + keyValue);
                throw new IllegalStateException("Key does not exist: " + keyValue);
            }
        }

        // Insert into blocked_models table
        String insertSql = "INSERT INTO blocked_models (key_value, model_name) VALUES (?, ?)";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setString(1, keyValue);
            stmt.setString(2, modelName);
            stmt.executeUpdate();
            Logger.info("Blocked model '" + modelName + "' for key ID " + keyValue);
        }
        catch (SQLException e){
            e.printStackTrace();
            Logger.log("Something went wrong");
        }
    }

    /**
     * Removes a blocked model entry for the given key in the {@code blocked_models} table.
     *
     * <p>This method allows previously blocked models to be unblocked for a specific key.
     * It first checks if the key exists in the {@code keys} table. If the key does not exist,
     * an {@link IllegalStateException} is thrown.</p>
     *
     * <p>Logging is performed at each stage:
     * <ul>
     *     <li>Warnings are logged if the key does not exist or the model was not blocked</li>
     *     <li>Info is logged when a model is successfully unblocked for a key</li>
     * </ul></p>
     *
     * @param keyValue      the unique ID of the key in the {@code keys} table
     * @param modelName  the name of the model to unblock for this key
     *
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     * @throws IllegalStateException if the key does not exist
     */
    public static synchronized void unblockModelForKey(String keyValue, String modelName) throws SQLException {
        // Check if key exists
        String keyCheckSql = "SELECT value FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement checkStmt = conn.prepareStatement(keyCheckSql)) {
            checkStmt.setString(1, keyValue);
            ResultSet rs = checkStmt.executeQuery();

            if (!rs.next()) {
                Logger.warn("No key found with ID: " + keyValue);
                throw new IllegalStateException("Key does not exist: " + keyValue);
            }
        }

        // Delete the blocked model
        String deleteSql = "DELETE FROM blocked_models WHERE key_value = ? AND model_name = ?";
        try (Connection conn = connect(); PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
            deleteStmt.setString(1, keyValue);
            deleteStmt.setString(2, modelName);

            int affectedRows = deleteStmt.executeUpdate();
            if (affectedRows > 0) {
                Logger.info("Unblocked model '" + modelName + "' for key ID " + keyValue);
            } else {
                Logger.warn("Model '" + modelName + "' was not blocked for key ID " + keyValue);
            }
        }
    }
    /**
     * Checks whether a given key is allowed to use a specific model.
     *
     * <p>This method queries the {@code blocked_models} table to determine if the key
     * has a restriction for the given model. If there is no entry in {@code blocked_models}
     * for the key and model, the key is allowed to use it.</p>
     *
     * <p>Logging is performed at each stage:
     * <ul>
     *     <li>Info is logged whether the key is allowed or blocked for the model</li>
     *     <li>Warnings are logged if the key does not exist</li>
     * </ul></p>
     *
     * @param keyValue      the unique ID of the key in the {@code keys} table
     * @param modelName  the name of the model to check
     *
     * @return {@code true} if the key can use the model, {@code false} if blocked
     * @throws SQLException if a database access error occurs or the SQL statement is invalid
     * @throws IllegalStateException if the key does not exist
     */
    public static synchronized boolean canKeyUseModel(String keyValue, String modelName) throws SQLException {
        // Check if the key exists
        String keyCheckSql = "SELECT value FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement checkStmt = conn.prepareStatement(keyCheckSql)) {
            checkStmt.setString(1, keyValue);
            ResultSet rs = checkStmt.executeQuery();

            if (!rs.next()) {
                Logger.warn("No key found with ID: " + keyValue);
                throw new IllegalStateException("Key does not exist: " + keyValue);
            }
        }

        // Check if the model is blocked
        String sql = "SELECT COUNT(*) AS count FROM blocked_models WHERE key_value = ? AND model_name = ?";
        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, keyValue);
            stmt.setString(2, modelName);
            ResultSet rs = stmt.executeQuery();

            rs.next();
            boolean allowed = rs.getInt("count") == 0;

            if (allowed) {
                Logger.info("Key ID " + keyValue + " is allowed to use model '" + modelName + "'.");
            } else {
                Logger.info("Key ID " + keyValue + " is BLOCKED from using model '" + modelName + "'.");
            }

            return allowed;
        }
    }
    /**
     * Retrieves a list of models that the given key is allowed to use.
     *
     * <p>This method queries all models from the {@code models} table and excludes any
     * that are blocked for the given key in the {@code blocked_models} table. The result
     * is a list of models the key can actually access.</p>
     *
     * <p>Logging is performed:
     * <ul>
     *     <li>Warnings if the key does not exist</li>
     *     <li>Info showing how many models are allowed</li>
     * </ul></p>
     *
     * @param keyValue the unique ID of the key in the {@code keys} table
     * @return a {@link ArrayList} of model names that the key is allowed to use
     * @throws SQLException if a database access error occurs
     * @throws IllegalStateException if the key does not exist
     */
    public static synchronized ArrayList<String> getBlockedModelsForKey(String keyValue) throws SQLException {
        // Check if the key exists
        String keyCheckSql = "SELECT value FROM keys WHERE value = ?";
        try (Connection conn = connect(); PreparedStatement checkStmt = conn.prepareStatement(keyCheckSql)) {
            checkStmt.setString(1, keyValue);
            ResultSet rs = checkStmt.executeQuery();

            if (!rs.next()) {
                Logger.warn("No key found with ID: " + keyValue);
                throw new IllegalStateException("Key does not exist: " + keyValue);
            }
        }

        String sql = "SELECT model_name FROM blocked_models WHERE key_value = ?";

        try (Connection conn = connect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, keyValue);
            ResultSet rs = stmt.executeQuery();

            ArrayList<String> allowedModels = new ArrayList<>();
            while (rs.next()) {
                allowedModels.add(rs.getString("model_name"));
            }

            Logger.info("Key ID " + keyValue + " is allowed to use " + allowedModels.size() + " models.");
            return allowedModels;
        }
    }

}

