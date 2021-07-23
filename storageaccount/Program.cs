// 
// Copyright (c) Microsoft.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Azure;
using Azure.Storage;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Azure.Storage.Sas;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.Azure.Management.ResourceManager.Models;
using Microsoft.Azure.Management.Storage;
using Microsoft.Azure.Management.Storage.Models;
using Microsoft.Rest;

/// <summary>
/// Azure Storage Resource Provider Sample - Demonstrate how to create and manage storage accounts using Storage Resource Provider. 
/// Azure Storage Resource Provider enables customers to create and manage storage accounts 
///  
/// Documentation References: 
/// - How to create, manage, or delete a storage account in the Azure Portal - https://azure.microsoft.com/en-us/documentation/articles/storage-create-storage-account/
/// - Storage Resource Provider REST API  documentation - https://msdn.microsoft.com/en-us/library/azure/mt163683.aspx 
/// </summary>

namespace AzureStorageNew
{
    public class StorageAccountTests
    {
        // You can locate your subscription ID on the Subscriptions blade of the Azure Portal (https://portal.azure.com).
        const string subscriptionId = "";

        //Specify a resource group name of your choice. Specifying a new value will create a new resource group.
        const string rgName = "";

        //Storage Account Name. Using random value to avoid conflicts.  Replace this with a storage account of your choice.
        static string accountName = "storagesample" + Guid.NewGuid().ToString().Substring(0, 8);

        // To run the sample, you must first create an Azure service principal. To create the service principal, follow one of these guides:
        //      Azure Portal: https://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/) 
        //      PowerShell: https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/
        //      Azure CLI: https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/
        // Creating the service principal will generate the values you need to specify for the constansts below.

        // Use the values generated when you created the Azure service principal.
        const string applicationId = "";
        const string password = "";
        const string tenantId = "";

        // These values are used by the sample as defaults to create a new storage account. You can specify any location and any storage account type.
        const string DefaultLocation = "westus";
        public static Microsoft.Azure.Management.Storage.Models.Sku DefaultSku = new Microsoft.Azure.Management.Storage.Models.Sku(Microsoft.Azure.Management.Storage.Models.SkuName.StandardGRS);
        public static Dictionary<string, string> DefaultTags = new Dictionary<string, string>
        {
            {"key1","value1"},
            {"key2","value2"}
        };

        //The following method will enable you to use the token to create credentials
        private static async Task<string> GetAuthorizationHeader()
        {
            ClientCredential cc = new ClientCredential(applicationId, password);
            var context = new AuthenticationContext("https://login.windows.net/" + tenantId);
            var result = await context.AcquireTokenAsync("https://management.azure.com/", cc);

            if (result == null)
            {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            string token = result.AccessToken;

            return token;
        }

        static async Task Main(string[] args)
        {
            Console.WriteLine("in the main ");
            string token = GetAuthorizationHeader().Result;
            Console.WriteLine("token: " + token);
            TokenCredentials credential = new TokenCredentials(token);
            ResourceManagementClient resourcesClient = new ResourceManagementClient(credential) { SubscriptionId = subscriptionId };
            StorageManagementClient storageMgmtClient = new StorageManagementClient(credential) { SubscriptionId = subscriptionId };

            try
            {
                //Register the Storage Resource Provider with the Subscription
                RegisterStorageResourceProvider(resourcesClient);

                //Create a new resource group
                //CreateResourceGroup(rgName, resourcesClient);
                //Console.WriteLine("create resource group");

                //Create a new account in a specific resource group with the specified account name                     
                //CreateStorageAccount(rgName, accountName, storageMgmtClient);
                //Console.WriteLine("create storage account ");

                //CreateBlobContainer(rgName, accountName, "blobcontainer1", storageMgmtClient);

                //Get all the account properties for a given resource group and account name
                // StorageAccount storAcct = storageMgmtClient.StorageAccounts.GetProperties(rgName, accountName);

                //Get a list of storage accounts within a specific resource group
                // IEnumerable<StorageAccount> storAccts = storageMgmtClient.StorageAccounts.ListByResourceGroup(rgName);

                //Get all the storage accounts for a given subscription
                // IEnumerable<StorageAccount> storAcctsSub = storageMgmtClient.StorageAccounts.List();

                //Get the storage account keys for a given account and resource group
                // IList<StorageAccountKey> acctKeys = storageMgmtClient.StorageAccounts.ListKeys(rgName, accountName).Keys;

                //Regenerate the account key for a given account in a specific resource group
                // IList<StorageAccountKey> regenAcctKeys = storageMgmtClient.StorageAccounts.RegenerateKey(rgName, accountName, "key1").Keys;

                //Update the storage account for a given account name and resource group
                // UpdateStorageAccountSku(rgName, accountName, SkuName.StandardLRS, storageMgmtClient);

                //Check if the account name is available
                // bool? nameAvailable = storageMgmtClient.StorageAccounts.CheckNameAvailability(accountName).NameAvailable;

                //Delete a storage account with the given account name and a resource group
                // DeleteStorageAccount(rgName, "storagesample10edb01d", storageMgmtClient);

                //DeleteBlobContainer(rgName, "storagesample27636155", "blobcontainer1", storageMgmtClient);

                //await CheckFile(rgName, "storagesample27636155", "provisioningscript-v2-3-0", "setup.ps1");

                await copyBlob("https://provisioningscript.blob.core.windows.net", "https://copystorageaccounttest.blob.core.windows.net");

                //Uri uri = await GenerateSASToken(rgName, "provisioningscript", "provisioningscript-v2-3-0", "setup.ps1");
                //Console.WriteLine("Uri: " + uri.ToString());

                Console.WriteLine("End");
                Console.ReadLine();
            }
            catch (Exception e)
            {
                Console.WriteLine("catch");
                Console.WriteLine(e.Message);
                Console.ReadLine();
            }
        }

        /// <summary>
        /// Registers the Storage Resource Provider in the subscription.
        /// </summary>
        /// <param name="resourcesClient"></param>
        public static void RegisterStorageResourceProvider(ResourceManagementClient resourcesClient)
        {
            Console.WriteLine("Registering Storage Resource Provider with subscription...");
            resourcesClient.Providers.Register("Microsoft.Storage");
            Console.WriteLine("Storage Resource Provider registered.");
        }

        /// <summary>
        /// Creates a new resource group with the specified name
        /// If one already exists then it gets updated
        /// </summary>
        /// <param name="resourcesClient"></param>
        public static void CreateResourceGroup(string rgname, ResourceManagementClient resourcesClient)
        {
            Console.WriteLine("Creating a resource group...");
            var resourceGroup = resourcesClient.ResourceGroups.CreateOrUpdate(
                    rgname,
                    new ResourceGroup
                    {
                        Location = DefaultLocation
                    });
            Console.WriteLine("Resource group created with name " + resourceGroup.Name);

        }

        /// <summary>
        /// Create a new Storage Account. If one already exists then the request still succeeds
        /// </summary>
        /// <param name="rgname">Resource Group Name</param>
        /// <param name="acctName">Account Name</param>
        /// <param name="useCoolStorage">Use Cool Storage</param>
        /// <param name="useEncryption">Use Encryption</param>
        /// <param name="storageMgmtClient">Storage Management Client</param>
        private static void CreateStorageAccount(string rgname, string acctName, StorageManagementClient storageMgmtClient)
        {
            StorageAccountCreateParameters parameters = GetDefaultStorageAccountParameters();

            Console.WriteLine("Creating a storage account...");
            var storageAccount = storageMgmtClient.StorageAccounts.Create(rgname, acctName, parameters);
            Console.WriteLine("Storage account created with name " + storageAccount.Name);
        }

        /// <summary>
        /// Deletes a storage account for the specified account name
        /// </summary>
        /// <param name="rgname"></param>
        /// <param name="acctName"></param>
        /// <param name="storageMgmtClient"></param>
        private static void DeleteStorageAccount(string rgname, string acctName, StorageManagementClient storageMgmtClient)
        {
            Console.WriteLine("Deleting a storage account...");
            storageMgmtClient.StorageAccounts.Delete(rgname, acctName);
            Console.WriteLine("Storage account " + acctName + " deleted");
        }

        /// <summary>
        /// Create a new blob container. If one already exists then the request still succeeds
        /// </summary>
        /// <param name="rgname">Resource Group Name</param>
        /// <param name="acctName">Account Name</param>
        /// <param name="containerName"></param>
        /// <param name="storageMgmtClient">Storage Management Client</param>
        private static async Task CreateBlobContainer(string rgname, string acctName, string containerName, StorageManagementClient storageMgmtClient)
        {
            Console.WriteLine("Creating a blob container...");
            var blobContainer = await storageMgmtClient.BlobContainers.CreateAsync(rgname, acctName, containerName);
            Console.WriteLine("Blob container created with name " + blobContainer.Name);
        }

        /// <summary>
        /// Deletes a blob container for the specified container name
        /// </summary>
        /// <param name="rgname"></param>
        /// <param name="acctName"></param>
        /// <param name="containerName"></param>
        /// <param name="storageMgmtClient"></param>
        private static void DeleteBlobContainer(string rgname, string acctName, string containerName, StorageManagementClient storageMgmtClient)
        {
            Console.WriteLine("Deleting a blob container...");
            storageMgmtClient.BlobContainers.Delete(rgname, acctName, containerName);
            Console.WriteLine("Blob container " + containerName + " deleted");
        }

        private static async Task CheckFile(string rgname, string acctName, string containerName, string fileName)
        {
            Console.WriteLine("checking file...");
            Uri blobContainerUri = new Uri("https://provisioningscript.blob.core.windows.net/provisioningscript-v2-3-0");
            BlobContainerClient container = new BlobContainerClient(blobContainerUri);
            //bool containerExist = false;
            //containerExist = await container.ExistsAsync();
            //try
            //{
            //    containerExist = await container.ExistsAsync();
            //}
            //catch (RequestFailedException ex)
            //{
            //    Console.WriteLine("RequestFailedException");
            //}

            //if (!containerExist)
            //{
            //    Console.WriteLine("containerExist: false");
            //}

            BlobClient blobClient = container.GetBlobClient(fileName);
            Console.WriteLine("blobClient");
            bool blobExist = false;
            try
            {
                blobExist = await blobClient.ExistsAsync();
            }
            catch (RequestFailedException ex)
            {
                // AuthenticationFailed, NoAuthenticationInformation(no sas token for blobContainerUri)
                Console.WriteLine("RequestFailedException: " + ex.ErrorCode);
                // Service request failed.
                Console.WriteLine("RequestFailedException: " + ex.Message);
            }
            Console.WriteLine("blobExist: " + blobExist);
            if (!blobExist)
            {
                Console.WriteLine("The " + fileName + " doesn't exist");
            }
            else
            {
                Console.WriteLine("blobExist");
            }
        }

        private static async Task copyBlob(string sourceStorageAccountURL, string destStorageAccountURL)
        {
            Console.WriteLine("copying blobs...");
            //way1:
            //Uri sourceBlobContainerUri = new Uri(sourceStorageAccountURL);
            ////storage account level SAS
            //string SASToken1 = "";
            //AzureSasCredential sas1 = new AzureSasCredential(SASToken1);
            //BlobServiceClient sourceBlobServiceClient = new BlobServiceClient(sourceBlobContainerUri, sas1);

            //Uri destBlobContainerUri = new Uri(destStorageAccountURL);
            //string SASToken2 = "";
            //AzureSasCredential sas2 = new AzureSasCredential(SASToken2);
            //BlobServiceClient destBlobServiceClient = new BlobServiceClient(destBlobContainerUri, sas2);

            //BlobContainerClient sourceContainer = sourceBlobServiceClient.GetBlobContainerClient("provisioningscript-v2-3-0");
            //BlobContainerClient destContainer = destBlobServiceClient.GetBlobContainerClient("copycontainer");

            //way2:AuthorizationPermissionMismatch

            //Uri sourceBlobContainerUri = new Uri("https://provisioningscript.blob.core.windows.net/provisioningscript-v2-3-0?sp=r&st=2021-07-21T16:46:02Z&se=2021-07-23T00:46:02Z&spr=https&sv=2020-08-04&sr=c&sig=CZkBhs9InUzIZESyZGYaVqPM7XSXGiWePHmGtR%2FLCUo%3D");
            //BlobContainerClient sourceContainer = new BlobContainerClient(sourceBlobContainerUri);

            ////var sourceBlobs = sourceContainer.GetBlobs();

            //Uri destBlobContainerUri = new Uri("https://copystorageaccounttest.blob.core.windows.net/copycontainer?sp=r&st=2021-07-21T16:47:56Z&se=2021-07-23T00:47:56Z&spr=https&sv=2020-08-04&sr=c&sig=EEDvtnwvxlXourpT5lrJdCtbcTySSVdxuWrbvAGfOI4%3D");
            //BlobContainerClient destContainer = new BlobContainerClient(destBlobContainerUri);


            ////var sourceBlobClient = sourceContainer.GetBlobClient("setup.ps1");
            ////sourceBlobClient.GenerateSasUri();


            //Uri sourceBlobUri = new Uri("https://provisioningscript.blob.core.windows.net/provisioningscript-v2-3-0/setup.ps1");
            //var destBlobClient = destContainer.GetBlobClient("setup.ps1");

            //CopyFromUriOperation status;
            //status = await destBlobClient.StartCopyFromUriAsync(sourceBlobUri);

            //try 
            //{
            //    status = await destBlobClient.StartCopyFromUriAsync(sourceBlobUri);
            //}
            //// no sas token for the uri
            //catch(RequestFailedException ex)
            //{
            //    // CannotVerifyCopySource
            //    Console.WriteLine("RequestFailedException: " + ex.ErrorCode);
            //    //  Server failed to authenticate the request. Please refer to the information in the www-authenticate header.
            //    Console.WriteLine("RequestFailedException: " + ex.Message);
            //    // 401
            //    Console.WriteLine("RequestFailedException: " + ex.Status);
            //}

            //foreach (var blob in sourceBlobs)
            //{
            //    Console.WriteLine("start copying each blob: " + blob.Name);
            //    var sourceBlobClient = sourceContainer.GetBlobClient(blob.Name);
            //    var destBlobClient = destContainer.GetBlobClient(blob.Name);
            //    string uri = "https://provisioningscript.blob.core.windows.net/provisioningscript-v2-3-0/" + blob.Name + "?";
            //    string sastoken = "sp=r&st=2021-07-20T22:11:49Z&se=2021-07-21T06:11:49Z&spr=https&sv=2020-08-04&sr=b&sig=bgRlxh1xp1u%2FWaOgC%2BygecZEobPOUJ0Chs1gVal9aNM%3D";
            //    var sourceBlobUri = new Uri(uri + sastoken);
            //    //var sourceBlobUri = sourceBlobClient.Uri;
            //    Console.WriteLine("sourceBlobUri: " + sourceBlobUri.AbsoluteUri);
            //    // await destBlobClient.StartCopyFromUriAsync(sourceBlobUri);
            //    CopyFromUriOperation status = await destBlobClient.StartCopyFromUriAsync(sourceBlobUri);
            //    if (!status.HasCompleted)
            //    {
            //        Console.WriteLine("Blob failed to copy over");
            //    }
            //}

            // way3
            StorageSharedKeyCredential sourceCredential = new StorageSharedKeyCredential("provisioningscript", "oCAecZ6wgNhdILKhFakIky0ovi0Q12rVrKN+Q2RuWuS5rVtDtNrA8hn9fPLGvV4a5KCxcKXIzRlZLD13K9qcPQ==");
            Uri sourceStorageAccountUri = new Uri(sourceStorageAccountURL);
            // storage account level SAS
            string sasToken1 = GetAccountSASToken(sourceCredential);
            AzureSasCredential sas1 = new AzureSasCredential(sasToken1);
            BlobServiceClient sourceBlobServiceClient = new BlobServiceClient(sourceStorageAccountUri, sas1);
            Console.WriteLine("sourceBlobServiceClient");

            StorageSharedKeyCredential destCredential = new StorageSharedKeyCredential("copystorageaccounttest", "vD0QvXIi49Q6dz+h0JCZ3nIWfrVW9ABYmNaz8bDiadSsKbOB+eP4zN0Zush6J64K/eyPFdnNZOFzrydSZl8k3Q==");
            Uri destStorageAccountUri = new Uri(destStorageAccountURL);
            string sasToken2 = GetAccountSASToken(destCredential);
            AzureSasCredential sas2 = new AzureSasCredential(sasToken2);
            BlobServiceClient destBlobServiceClient = new BlobServiceClient(destStorageAccountUri, sas2);
            Console.WriteLine("destBlobServiceClient");

            BlobContainerClient sourceContainer = sourceBlobServiceClient.GetBlobContainerClient("provisioningscript-v2-3-0");
            Console.WriteLine("sourceContainer");
            BlobContainerClient destContainer = destBlobServiceClient.GetBlobContainerClient("copycontainer");
            Console.WriteLine("destContainer");

            AsyncPageable<BlobItem> sourceBlobs = sourceContainer.GetBlobsAsync();
            Console.WriteLine("sourceBlobs");

            await foreach (BlobItem blob in sourceBlobs)
            {
                Console.WriteLine("start copying each blob");
                Console.WriteLine(blob.Name);
                //var sourceBlobClient = sourceContainer.GetBlobClient(blob.Name);

                var sourceBlobUri = string.Format("https://provisioningscript.blob.core.windows.net/provisioningscript-v2-3-0/{0}", blob.Name);
                Console.WriteLine("sourceBlobUri");
                //directly build BlobClient, then pass it to GetServiceSasUriForBlob() method
                BlobClient sourceBlobClient = new BlobClient(new Uri(sourceBlobUri), sourceCredential);
                Console.WriteLine("sourceBlobClient");
                var destBlobClient = destContainer.GetBlobClient(blob.Name);
                Console.WriteLine("destBlobClient");
                // var sourceBlobUri = new Uri($"{sourceBlobClient.Uri.AbsoluteUri}");
                var sourceSasBlobUri = GetServiceSasUriForBlob(sourceBlobClient);
                Console.WriteLine("sourceSasBlobUri");
                // await destBlobClient.StartCopyFromUriAsync(sourceBlobUri);
                CopyFromUriOperation status;
                try
                {
                    status = await destBlobClient.StartCopyFromUriAsync(sourceSasBlobUri);
                    Console.WriteLine("status");
                    if (!status.HasCompleted)
                    {
                        Console.WriteLine("Blob " + blob.Name + " failed to copy over");
                    }
                }
                catch (RequestFailedException ex)
                {
                    Console.WriteLine("1ES doesn't have permission to access the container: " + sourceContainer.Name);
                }
            }

            //IAsyncEnumerator<BlobItem> enumerator = sourceBlobs.GetAsyncEnumerator();
            //Console.WriteLine("enumerator");
            //try
            //{
            //    while (await enumerator.MoveNextAsync())
            //    {
            //        Console.WriteLine("while");
            //        BlobItem blob = enumerator.Current;
            //        Console.WriteLine(blob.Name);
            //    }
            //}
            //finally
            //{
            //    await enumerator.DisposeAsync();
            //}
        }

        private static string GetAccountSASToken(StorageSharedKeyCredential credential)
        {
            Console.WriteLine("generationg storage account sas token...");

            // Create a SAS token that's valid for one hour.
            AccountSasBuilder sasBuilder = new AccountSasBuilder()
            {
                Services = AccountSasServices.Blobs | AccountSasServices.Files,
                ResourceTypes = AccountSasResourceTypes.All,
                ExpiresOn = DateTimeOffset.UtcNow.AddHours(1),
                Protocol = SasProtocol.Https
            };
            Console.WriteLine("sasBuilder");
            sasBuilder.SetPermissions(AccountSasPermissions.All);
            Console.WriteLine("SetPermissions");

            // Use the key to get the SAS token.
            string sasToken = sasBuilder.ToSasQueryParameters(credential).ToString();

            Console.WriteLine("SAS token for the storage account is: {0}", sasToken);
            Console.WriteLine();

            return sasToken;
        }

        private static Uri GetServiceSasUriForBlob(BlobClient blobClient, string storedPolicyName = null)
        {
            Console.WriteLine("generationg blob sas token...");
            // Check whether this BlobClient object has been authorized with Shared Key.
            if (blobClient.CanGenerateSasUri)
            {
                // Create a SAS token that's valid for one hour.
                BlobSasBuilder sasBuilder = new BlobSasBuilder()
                {
                    BlobContainerName = blobClient.GetParentBlobContainerClient().Name,
                    BlobName = blobClient.Name,
                    Resource = "b"
                };
                Console.WriteLine("sasBuilder");

                if (storedPolicyName == null)
                {
                    Console.WriteLine("storedPolicyName is null");
                    sasBuilder.ExpiresOn = DateTimeOffset.UtcNow.AddHours(1);
                    sasBuilder.SetPermissions(BlobSasPermissions.All);
                }
                else
                {
                    sasBuilder.Identifier = storedPolicyName;
                }

                Uri sasUri = blobClient.GenerateSasUri(sasBuilder);
                Console.WriteLine("SAS URI for blob is: {0}", sasUri);
                Console.WriteLine();

                return sasUri;
            }
            else
            {
                Console.WriteLine("BlobClient must be authorized with Shared Key credentials to create a service SAS.");
                return null;
            }
        }

        private static async Task<Uri> GenerateSASToken(string rgname, string acctName, string containerName, string blobName)
        {
            Console.WriteLine("Generating sas token...");
            string blobEndpoint = string.Format("https://{0}.blob.core.windows.net", acctName);
            Console.WriteLine("blobEndpoint: " + blobEndpoint);

            BlobServiceClient blobClient = new BlobServiceClient(new Uri(blobEndpoint),
                                                     new DefaultAzureCredential());
            Console.WriteLine("blobClient");

            Azure.Storage.Blobs.Models.UserDelegationKey key = await blobClient.GetUserDelegationKeyAsync(DateTimeOffset.UtcNow,
                                                                   DateTimeOffset.UtcNow.AddDays(7));
            Console.WriteLine("key");
            // Read the key's properties.
            Console.WriteLine("User delegation key properties:");
            Console.WriteLine("Key signed start: {0}", key.SignedStartsOn);
            Console.WriteLine("Key signed expiry: {0}", key.SignedExpiresOn);
            Console.WriteLine("Key signed object ID: {0}", key.SignedObjectId);
            Console.WriteLine("Key signed tenant ID: {0}", key.SignedTenantId);
            Console.WriteLine("Key signed service: {0}", key.SignedService);
            Console.WriteLine("Key signed version: {0}", key.SignedVersion);

            // Create a SAS token that's also valid for 7 days.
            BlobSasBuilder sasBuilder = new BlobSasBuilder()
            {
                BlobContainerName = containerName,
                BlobName = blobName,
                Resource = "b",
                StartsOn = DateTimeOffset.UtcNow,
                ExpiresOn = DateTimeOffset.UtcNow.AddDays(7)
            };

            Console.WriteLine("sasBuilder");

            // Specify read and write permissions for the SAS.
            sasBuilder.SetPermissions(BlobSasPermissions.Read |
                                      BlobSasPermissions.Write);
            Console.WriteLine("SetPermissions");

            BlobSasQueryParameters sasToken = sasBuilder.ToSasQueryParameters(key, acctName);
            Console.WriteLine("sasToken");

            // Add the SAS token to the blob URI.
            BlobUriBuilder blobUriBuilder = new BlobUriBuilder(blobClient.Uri)
            {
                // Specify the user delegation key.
                Sas = sasBuilder.ToSasQueryParameters(key, acctName)
            };
            Console.WriteLine("blobUriBuilder");
            Console.WriteLine("Blob user delegation SAS URI: {0}", blobUriBuilder);
            Console.WriteLine("sasToken: " + sasToken.ToString());
            return blobUriBuilder.ToUri();
        }

        /// <summary>
        /// Updates the storage account
        /// </summary>
        /// <param name="rgname">Resource Group Name</param>
        /// <param name="acctName">Account Name</param>
        /// <param name="storageMgmtClient"></param>
        private static void UpdateStorageAccountSku(string rgname, string acctName, string skuName, StorageManagementClient storageMgmtClient)
        {
            Console.WriteLine("Updating storage account...");
            // Update storage account sku
            var parameters = new StorageAccountUpdateParameters
            {
                Sku = new Microsoft.Azure.Management.Storage.Models.Sku(skuName)
            };
            var storageAccount = storageMgmtClient.StorageAccounts.Update(rgname, acctName, parameters);
            Console.WriteLine("Sku on storage account updated to " + storageAccount.Sku.Name);
        }

        /// <summary>
        /// Returns default values to create a storage account
        /// </summary>
        /// <returns>The parameters to provide for the account</returns>
        private static StorageAccountCreateParameters GetDefaultStorageAccountParameters()
        {
            StorageAccountCreateParameters account = new StorageAccountCreateParameters
            {
                Location = DefaultLocation,
                Kind = Kind.StorageV2,
                Tags = DefaultTags,
                Sku = DefaultSku
            };

            return account;
        }
    }
}
