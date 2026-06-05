# BOTS v3 Attack-Chain Citation Table — botsv3/attack_chain

**Coverage: 13 / 13 checkpoints (100%)** on the attack-chain subset. Trivia questions are out of scope for triage and excluded by design.

| BOTS Q | Category | Official answer | Agent finding | Result |
| --- | --- | --- | --- | --- |
| Q333 | initial_access | Initial access via Apache Struts OGNL RCE on the public-facing web server. | mapped T1190 | ✅ match |
| Q333 | initial_access | Struts RCE is CVE-2017-9791 (S2-048), the Showcase/Struts1-plugin vector. | asserted in verdict | ✅ match |
| Q333 | execution | Post-exploitation backdoor runs as tomcat7 with UID=0. | mapped T1505.003, T1059 | ✅ match |
| Q328 | privilege_escalation | Local privilege escalation to root via kernel exploit. | mapped T1068 | ✅ match |
| Q332 | privilege_escalation | Kernel LPE is CVE-2017-16995 (eBPF verifier). | asserted in verdict | ✅ match |
| Q200 | persistence | IAM abuse via the web_admin identity. | mapped T1078, T1098 | ✅ match |
| Q200 | impact | AWS resource hijacking — RunInstances launching cryptomining instances. | mapped T1496 | ✅ match |
| Q323 | command_and_control | Command-and-control channel from compromised endpoints. | mapped T1071 | ✅ match |
| Q323 | command_and_control | C2 is a reverse shell to 45.77.53.176:8088 via /tmp/backpipe. | asserted in verdict | ✅ match |
| Q310 | initial_access_windows | Windows initial access via malicious .xlsm phishing attachment. | asserted in verdict | ✅ match |
| Q317 | execution_windows | Windows backdoor binary hdoor.exe executed. | asserted in verdict | ✅ match |
| Q304 | persistence_windows | Windows persistence via the svcvnc service. | asserted in verdict | ✅ match |
| Q320 | credential_access_windows | Credential access — password Password123! recovered. | asserted in verdict | ✅ match |
