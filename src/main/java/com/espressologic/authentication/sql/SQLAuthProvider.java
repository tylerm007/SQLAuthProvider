package com.espressologic.authentication.sql;



/**
 * This is a sample auth provider using mysql
 * author: tband
 * Date: June 2014
 */

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SQLAuthProvider {

	// change the driver to SQL Server or Postgres, etc
	private static final String driverType = "jdbc:mysql";
	private String server = "localhost";
	private String port = "3306";
	private String database = "sample";

	public SQLAuthProvider() {

	}

	public SQLAuthProvider(String server, String port, String database) {
		this.server = server;
		this.port = port;
		this.database = database;
	}

	public static void main(String[] args) {
		String query = "select Territory from employees";
		SQLAuthProvider sap = new SQLAuthProvider("localhost","3306","sample");
		try {
			System.out.println(sap.authenticate("tyler", "password1", query));
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("done");
	}

	public String authenticate(String user, String pw, String query) throws ClassNotFoundException, SQLException {

		String url = driverType + "://" + this.server + ":" + this.port + "/" + this.database + "?";
		return authenticate(url, user, pw, query);
	}

	private String authenticate(String url, String user, String pw, String query) throws ClassNotFoundException, SQLException {
		StringBuffer sb = new StringBuffer();
		sb.append("{");
		Connection connect = null;
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");

			// setup the connection with the DB.
			connect = DriverManager.getConnection(url + "user=" + user + "&password=" + pw + "");

			// statements allow to issue SQL queries to the database
			statement = connect.createStatement();
			// resultSet gets the result of the SQL query
			resultSet = statement.executeQuery(query);
			// use this to get the roles and return as JSON String { role:
			// "role1" , role: "role2" }
			String sep = "";
			while (resultSet.next()) {
				sb.append(sep);
				sb.append("\"role\":");
				sb.append("\"" + resultSet.getString(1) + "\"");
				sep = ",";
			}

		} catch (SQLException se) {
			throw se;
		} catch (ClassNotFoundException cnf) {
			throw cnf;
		} finally {
			if (connect != null)
				connect.close();
			if (statement != null)
				statement.close();
			if (resultSet != null)
				resultSet.close();
		}
		sb.append("}");
		return sb.toString();
	}
}
