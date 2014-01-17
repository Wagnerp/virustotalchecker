# History #

**v1.1.4**

- Updated RestSharp library to 104.2
- Added Proxy configuration to the Settings.xml file so you can define the proxy like so: http://192.168.0.1:8080

**v1.1.3**

- Fixed bug where an exception occurring in the VT library could cause the overall process to stop
- Modified the CSV output to include the permalink URL
- Modified the error handling in Checker.cs to log hashes where an error occurred
- Modified the error handling in Checker.cs to include a timeout to ensure that the ToS are not broken
- Modified the Hash.Response (VirusTotal.NET) property from byte to short as the API can return -2 if a resource is queued for scanning
- Modified the CacheChecker.ProcessFile to include more error handling

**v1.1.2**

- Fixed a null exception in the Checker object when checks are performed before the Checker object can be initialised. Thanks RussellH
- Modified the command line parameters so that you don't need to specify an output parameter if requesting a single hash e.g. single hash outputs to console only. Thanks RussellH

**v1.1.1**

- Fixed bug in the live mode where not all checks were live

**v1.1.0**

- Modified to perform multiple hash checks at once e.g. 4
- Updated the file mode to work on any size file
- Modified to store all positive scan results
- Modified command line parameters to include "m" mode option e.g. c=caching, d=database, l=live. This means that the "l" live command line parameter has been removed
- Modified database structure to hold the date the record was inserted into the database. This allows the record to "expire" after 30 days 

**v1.0.5**

- Modified to store and output the result of the Microsoft (Security Essentials) scan
 
**v1.0.4**

- Updated the config file to be SQL CE aware

**v1.0.3**

- Added Permalink, Response and Scan Date fields to the database (VirusTotal.Net library)
- Added the ability to import a JSON file that is produced from a virustotal-search pickle file. You need to run the supplied convert-pickle-to-json.py. The python script expects the input file to be called “virustotal-search.pkl”, the output file will be “virustotal-search.json”
- Fixed bug which cause an error if the resource could not be found on VT
- Added SHA256 support e.g. it stores it and you can search on it
- Removed the need to specify the hash type, now it just looks at the length e.g. 32 or 64 characters

**v1.0.2**

- Modified to allow for just live results
- Modified to update reports with 0/0 results
- Improved output for failed (0/0) results
- Updated the command line parameters to allow the user to select the database path


**v1.0.1**

- Initial public release