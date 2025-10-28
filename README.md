# API Guardian - AWS API Gateway Security Auditor

Automated security scanning and compliance auditing for AWS API Gateway resources.

## Features

- ✅ **Automated Authorization Scanning**: Identifies endpoints without proper authorization
- ✅ **Authorizer Auditing**: Details authorizer types and names
- ✅ **Automatic Filtering**: Excludes -DEV and -CI APIs
- ✅ **Endpoint Whitelist**: Exclude endpoints with backend authentication
- ✅ **Sequential API Analysis**: Clean, organized output per API
- ✅ **Parallel Resource Processing**: Fast scanning within each API
- ✅ **Optimized Caching**: 60-70% faster authorizer cache building
- ✅ **CSV Reports**: Real-time detailed reporting
- ✅ **API Key Detection**: Separate column for API Key requirements
- ✅ **Configurable Performance**: Adjustable worker pool sizes

## Quick Start

### Run Security Check

**Method 1: Direct Python**
```bash
python3 apiguardian.py
```

**Method 2: Using Launcher Script**
```bash
./run.sh
```

**Method 3: Installed via pip**
```bash
apiguardian
```

### Options

1. **Scan Specific API**: Audit a single API Gateway
2. **Scan All APIs**: Audit all APIs (except -DEV, -CI)
3. **Configure Pool Size**: Set resource parallelization (1-10)

## CSV Report Format

**Columns:**
- `api` - API Gateway name
- `method` - HTTP method (GET, POST, PUT, DELETE, PATCH)
- `path` - Endpoint path
- `is_authorized` - Has robust authorization (Cognito, Lambda, AWS IAM)
- `authorization_type` - Authorization type (NONE, COGNITO_USER_POOLS, CUSTOM, AWS_IAM)
- `specific_auth_type` - Specific type (ADMIN, CUSTOMER, NONE)
- `authorizer_name` - Authorizer name (or NONE)
- `api_key` - Requires API Key (YES/NO)
- `whitelisted` - In whitelist (YES/NO)

**Example:**
```csv
api,method,path,is_authorized,authorization_type,specific_auth_type,authorizer_name,api_key,whitelisted
MS-Discounts-Public-PROD,GET,/campaigns,YES,COGNITO_USER_POOLS,ADMIN,AdminProd,NO,NO
MS-Auth-Server-Public-PROD,POST,/oauth/token,NO,NONE,NONE,NONE,NO,YES
```

## Whitelist Configuration

### Purpose
Exclude endpoints that have authentication in the microservice backend (not API Gateway).

### File Location
`apiguardian/whitelist.json`

### Format
```json
{
  "whitelist": {
    "MS-Auth-Server-Public-PROD": [
      "/oauth/token",
      "/oauth/validate"
    ],
    "MS-jumio-Public-PROD": [
      "/jumio/verification/*"
    ]
  }
}
```

### Features
- **Exact match**: `/oauth/token` matches exactly
- **Wildcard patterns**: `/jumio/verification/*` matches `/jumio/verification/123`
- **Auto-loaded**: Whitelist loads automatically at startup
- **CSV indicator**: Whitelisted endpoints marked as `whitelisted=YES`

## Performance

**Cache Building:**
- Phase 1 (Resource Scanning): Parallel (10 workers default)
- Phase 2 (Authorizer Caching): Parallel (auto-scaled)
- **Speed**: 116 resources, 4 authorizers in 10-15 seconds (60-70% faster than sequential)

**Resource Analysis:**
- Configurable pool size (1-10 workers)
- Default: 5 workers
- Processing: As-completed pattern for real-time updates

## Architecture

### Sequential APIs, Parallel Resources

```
API 1 ────► Build Cache (parallel)
            Analyze Resources (parallel)
            ✓ Complete

API 2 ────► Build Cache (parallel)
            Analyze Resources (parallel)
            ✓ Complete

API N ────► Build Cache (parallel)
            Analyze Resources (parallel)
            ✓ Complete
```

### Results
- Clean, readable output per API
- No output confusion
- Fast analysis
- Configurable performance tuning

## Output Files

Generated in `reports/` directory:

- `{api-name}_report_{timestamp}.csv` - Per-API reports
- `security_audit_report_{timestamp}.csv` - Consolidated report
- `error_dump_{timestamp}.log` - Error logs

## AWS Requirements

**Permissions needed:**
- `apigateway:ListRestApis`
- `apigateway:GetResources`
- `apigateway:GetMethod`
- `apigateway:GetAuthorizer`

**Setup:**
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile
```

## Troubleshooting

### No results
- Check AWS credentials: `aws sts get-caller-identity`
- Verify IAM permissions for API Gateway
- Ensure APIs have resources

### Slow analysis
- Reduce pool size for lighter load
- Check network connectivity to AWS
- Verify IAM role has CloudTrail access (for metadata)

### Missing endpoints
- Whitelist may be excluding them: check `whitelist.json`
- OPTIONS methods are automatically filtered
- Undeployed resources won't appear

## Portable & Standalone

API Guardian is **completely decoupled** from the API Gateway Creator:

- ✅ Works independently in any directory
- ✅ No external dependencies (uses AWS CLI)
- ✅ Configuration files bundled with the tool
- ✅ Can be moved to separate repository
- ✅ Ready for pip installation

### Moving to a Separate Repository

To extract API Guardian as an independent project:

1. Copy the `apiguardian/` folder to a new repository
2. Update GitHub URL in `setup.py`
3. Install dependencies from `setup.py`
4. Push to GitHub and publish to PyPI

```bash
# Install locally from setup.py
pip install -e .

# Or publish to PyPI
python3 setup.py sdist bdist_wheel
twine upload dist/*
```

## License

See root LICENSE file

## Support

For issues and feature requests, visit the GitHub repository.
