### Alerts 

03:14. Three alerts land in your queue within 90 seconds, all from the same file server:

Alert 1 - vssadmin.exe executed: delete shadows /all /quiet

Alert 2 - Mass file modification: 4,000+ files renamed in 2 minutes, all gaining the extension .lkd

Alert 3 - CPU pinned at 98% on the same host

You've never seen the .lkd extension before. A quick search brings up nothing solid.
Before you do anything, you remember the email IT sent yesterday. They're rolling out a new archiving tool across the file servers this week, "expect elevated disk activity during off-peak hours." The rollout schedule attached shows this server listed for tonight.
Your isolation button disconnects the server from the network instantly. Finance opens in 5 hours, and that server holds their shared drives. Isolating it wrongly means a morning of downtime, an angry client, and an incident report with your name on it.

#### Explain how you would investigate and why?
