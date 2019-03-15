/**
 * Created by rz on 14.06.17.
 */

import org.bouncycastle.cert.X509AttributeCertificateHolder;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.*;
import java.util.Base64;

public class Database {
    // JDBC driver name and database URL
    static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    static final String DB_URL = "jdbc:mysql://localhost:3306/AC?autoReconnect=true&useSSL=false";

    //  Database credentials
    static final String USER = "root";
    static final String PASS = "password";


    public void inserting(BigInteger acparam, BigInteger pkcparam, String encoded) throws NamingException {
        InitialContext ctx;
        DataSource ds;
        Connection conn = null;
        Statement stmt = null;
        try {
            ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
            //ds = (DataSource) ctx.lookup("jdbc/MySQLDataSource");
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "INSERT INTO ACCredentials " + "VALUES (" + acparam + "," + pkcparam + "," + "'" + encoded + "'" + "," + null +")";
            int result = stmt.executeUpdate(sql);
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
    }

    public String getSerialNumber(BigInteger serialnumber) throws NamingException, IOException {
        X509AttributeCertificateHolder certificateHolder = null;
        Context ctx = new InitialContext();
        DataSource ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT * FROM ACCredentials WHERE AcSerial="+ serialnumber;
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                //Retrieve by column name
                String b_encoded = rs.getString("Certificate");
                if (b_encoded == null){
                    return "Certificate not found";
                }
                // Convert to AC object
                byte[] data = Base64.getUrlDecoder().decode(b_encoded);
                certificateHolder = new X509AttributeCertificateHolder(data);
                return b_encoded;
            }
            rs.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return null;
    }

    public String revokeCertificate(BigInteger serialnumber) throws NamingException, IOException, SQLException {
        X509AttributeCertificateHolder certificateHolder = null;
        Context ctx = new InitialContext();
        DataSource ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        int count;
        try {
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT COUNT(AcSerial) AS anzahl FROM ACCredentials WHERE AcSerial="+ serialnumber;
            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                //Retrieve by column name
                count = rs.getInt("anzahl");
                if (count == 1){
                    return insertrevokeserialnumber(serialnumber);
                }
                if (count == 0) {
                    return "No SerialNumber found";
                }
            }
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return null;
    }

    public String insertrevokeserialnumber(BigInteger serialnumber) throws NamingException {
        InitialContext ctx;
        DataSource ds;
        Connection conn = null;
        Statement stmt = null;
        try {
            ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
            //ds = (DataSource) ctx.lookup("jdbc/MySQLDataSource");
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "INSERT IGNORE INTO ACRevoked " + "VALUES (" + serialnumber + "," + null +")";
            int result = stmt.executeUpdate(sql);
            if (result == 1 ) {
                return "AC revoked";
            }else {
                return "AC couldn't be revoked";
            }
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return null;
    }
    public String selectacserial(BigInteger serialnumber) throws NamingException, IOException {
        //X509AttributeCertificateHolder certificateHolder = null;
        Context ctx = new InitialContext();
        DataSource ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT AcSerial FROM ACCredentials WHERE AcSerial="+ serialnumber;
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                //Retrieve by column name
                String acserial = rs.getString("AcSerial");
                BigInteger acserialinteger = new BigInteger(acserial);
                if (acserialinteger.equals(serialnumber)){
                }else {
                    return "ACSerialnumber not found";
                }
            }
            rs.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return "ACSerialnumber: valid";
    }

    public String verifybase64ac(String base64ac) throws NamingException, IOException {
        X509AttributeCertificateHolder certificateHolder = null;
        Context ctx = new InitialContext();
        DataSource ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT Certificate FROM ACCredentials WHERE Certificate =" + "'" + base64ac + "'";
            rs = stmt.executeQuery(sql);

            while (rs.next()) {
                //Retrieve by column name
                String AC = rs.getString("Certificate");
                if (base64ac.equals(AC)) {
                    return "Base64 AC matches";
                } else {
                    return "Base64 AC corrupted";
                }
            }
            rs.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return "";
    }

    public String verifyrevokedacserial(BigInteger serialnumber) throws NamingException, IOException {
        X509AttributeCertificateHolder certificateHolder = null;
        Context ctx = new InitialContext();
        DataSource ds = (DataSource) ctx.lookup("jdbc/MeinDatasourceJndiName");
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        int count;
        try {
            conn = ds.getConnection();
            stmt = conn.createStatement();
            String sql = "SELECT COUNT(AcSerial) AS anzahl FROM ACCredentials WHERE AcSerial="+ serialnumber;
            rs = stmt.executeQuery(sql);
            while (rs.next()) {
                //Retrieve by column name
                count = rs.getInt("anzahl");
                if (count == 1){
                    return "AC is revoked";
                }
                if (count == 0) {
                    return "AC is not revoked";
                }
            }
            rs.close();
        } catch (SQLException se) {
            se.printStackTrace();
        } finally {
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return "";
    }
    public static int GetNextFreeSerialNumber() throws ClassNotFoundException, SQLException {
        Connection conn = null;
        Statement stmt = null;
        String sql = "SELECT COUNT(*) FROM ACCredentials";
        try {
            //STEP 2: Register JDBC driver
            Class.forName(JDBC_DRIVER);
            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                BigInteger lastUsed = BigInteger.valueOf(rs.getLong("Count(*)"));
                System.out.println(lastUsed);
                return lastUsed.intValue() + 1;
            }
            rs.close();
        } catch (SQLException se) {
            //Handle errors for JDBC
            se.printStackTrace();
        } catch (Exception e) {
            //Handle errors for Class.forName
            e.printStackTrace();
        } finally {
            //finally block used to close resources
            try {
                if (stmt != null)
                    conn.close();
            } catch (SQLException se) {
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
        return -1;
    }

}
