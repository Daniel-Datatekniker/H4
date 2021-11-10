using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurePassword
{
    class Database
    {
        private const string connectionstring = @"Server=(localdb)\MSSQLLocalDB;Integrated Security=true;Initial Catalog=h4;";
        SqlConnection cnn;
        public Database()
        {
            cnn = new SqlConnection(connectionstring);
            cnn.Open();
#if DEBUG
            Debug.WriteLine("Connection Open  !");
#endif
            cnn.Close();
        }

        public async Task<UserModel> NewUser(string name, string password)
        {
            using (SqlConnection connection = new SqlConnection(connectionstring))
            {
                string query = "INSERT INTO Users (username,HashedPassword) VALUES (@username,@HashedPassword)";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@username", name);
                    command.Parameters.AddWithValue("@HashedPassword", password);


                    connection.Open();
                    int result = await command.ExecuteNonQueryAsync();

                    // Check Error
                    if (result < 0)
                    {
#if DEBUG
                        Debug.WriteLine("Error inserting data into Database!");
                        return null;
#endif
                    }
                    return new UserModel(name, password);
                }
            }
        }


        public async Task<UserModel> GetUser(string name, string password)
        {

            using (SqlConnection connection = new SqlConnection(connectionstring))
            {
                using (SqlCommand myCommand = new SqlCommand("SELECT * FROM USERS WHERE USERNAME=@username AND HashedPassword=@HashedPassword", connection))
                {
                    myCommand.Parameters.AddWithValue("@Username", name);
                    myCommand.Parameters.AddWithValue("@HashedPassword", password);

                    connection.Open();
                    SqlDataReader myReader = myCommand.ExecuteReader();
                    if (myReader.HasRows)
                    {
                        await myReader.ReadAsync();
                        return new UserModel(myReader["Username"].ToString(), myReader["HashedPassword"].ToString());
                    }
                }
            }
            return null;
        }

    }
}
