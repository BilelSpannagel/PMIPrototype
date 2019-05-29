package hfu.pki.database;

import com.couchbase.client.java.*;
import com.couchbase.client.java.document.*;
import com.couchbase.client.java.document.json.*;
import com.couchbase.client.java.query.*;
import com.couchbase.client.java.bucket.BucketManager;

public class JDBC {

    private Bucket bucket;
    final BucketManager bucketManager;

    public JDBC() {
        // Initialize the Connection
        Cluster cluster = CouchbaseCluster.create("localhost");
        cluster.authenticate("test", "test");
        bucket = cluster.openBucket("test");

        // Create a N1QL Primary Index (but ignore if it exists)
        bucketManager = bucket.bucketManager();
        bucket.bucketManager().createN1qlPrimaryIndex(true, false);
    }

    // Create a JSON Document
    JsonObject arthur = JsonObject.create()
            .put("name", "Arthur")
            .put("email", "kingarthur@couchbase.com")
            .put("interests", JsonArray.from("Holy Grail", "African Swallows"));

    void storeDocument(JsonDocument jsonDocument){
        bucket.upsert(jsonDocument);
    }

    JsonDocument getDocument(String fileName){
        return bucket.get(fileName);
    }

    void printDocument(String fileName) {
        System.out.println(bucket.get(fileName));
    }

    // Perform a N1QL Query
    void N1QLQuery(String query) {
        N1qlQueryResult result = bucket.query(
                N1qlQuery.parameterized("SELECT name FROM `bucketname` WHERE $1 IN interests",
                        JsonArray.from(query))
        );

        // Print each found Row
        for (N1qlQueryRow row : result) {
            // Prints {"name":"Arthur"}
            System.out.println(row);
        }
    }
}