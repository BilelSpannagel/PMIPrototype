package hfu.pki.database;


import com.mongodb.*;
import com.mongodb.client.*;
import com.mongodb.client.MongoClient;
import hfu.pki.utils.Configurations;
import org.bson.Document;
import hfu.pki.database.JSONconverter;
import org.bson.conversions.Bson;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class JDBC {
    private static MongoCollection<Document> collection;
    private MongoDatabase database;
    private MongoClient mongoClient;
    public JDBC(){
        mongoClient = MongoClients.create(Configurations.DB_CONNECTION);
        database = mongoClient.getDatabase("test");
        collection = database.getCollection("certificates");
    }

    public static void insertIntoCollection(String fileName) throws IOException, CertificateException {
        collection.insertOne(JSONconverter.convertToJSONFromFile(fileName));
    }
    public static Document queryCollection(String id){
        Bson query = new BasicDBObject("id", id);
        FindIterable<Document> cursor = collection.find();
        for(Document doc : cursor){
            if(cursor == null){
                return null;
            }
            else{
                return doc;
            }
        }
        return null;
    }




}