rule SUSP_Blocked_Download_Proxy_Replacement_Jan23_1 {
   meta:
      description = "Detects a file that has been replaced with a note by a security solution like an Antivirus or a filtering proxy server"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/gui/search/filename%253A*.exe%2520tag%253Ahtml%2520size%253A10kb-%2520size%253A2kb%252B/files"
      date = "2023-01-28"
      score = 60
      id = "58bc8288-6bdb-57d5-9de5-a54a39584838"
   strings:
      $x01 = "Web Filter Violation"
      $x02 = "Google Drive can't scan this file for viruses."
      $x03 = " target=\"_blank\">Cloudflare <img "
      $x04 = "Sorry, this file is infected with a virus.</p>"
      $x05 = "-- Sophos Warn FileType Page -->"
      $x06 = "<p>Certain Sophos products may not be exported for use by government end-users"       $x07 = "<p class=\"content-list\">Bitly displays this warning when a link has been flagged as suspect. There are many"
      $x08 = "Something went wrong. Don't worry, your files are still safe and the Dropbox team has been notified."
      $x09 = "<p>sinkhole</p>"
      $x10 = "The requested short link is blocked by website administration due to violation of the website policy terms."
      $x11 = "<img src=\"https://www.malwarebytes.com/images/"
      $x12 = "<title>Malwarebytes</title>"
      $x13 = "<title>Blocked by VIPRE</title>"
      $x14 = "<title>Your request appears to be from an automated process</title>"
      $x15 = "<p>Advanced Security blocked access to"
      $x16 = "<title>Suspected phishing site | Cloudflare</title>"
      $x17 = ">This link has been flagged "
      $x18 = "<h1>Trend Micro Apex One</h1>"
      $x19 = "Hitachi ID Identity and Access Management Suite"
      $x20 = ">http://www.fortinet.com/ve?vn="
      $x21 = "access to URL with fixed IP not allowed"       $x23 = "<title>Web Page Blocked</title>"
      $x24 = "<title>Malicious Website Blocked</title>"
      $x25 = "<h2>STOPzilla has detected"
      $x26 = ">Seqrite Endpoint Security</span>"
      $x27 = "<TITLE>K7 Safe Surf</TITLE>"
      $x28 = "<title>Blocked by VIPRE</title>"

      $g01 = "blocked access" fullword
      $g02 = "policy violation" fullword
      $g03 = "violation of " 
      $g04 = "blocked by" fullword
      $g05 = "Blocked by" fullword
      $g07 = "Suspected Phishing"
      $g08 = "ile quarantined"
      $g09 = " is infected "
      $g10 = "Blocked</title>"
      $g11 = "site blocked" fullword
      $g12 = "Site Blocked" fullword
      $g13 = "blocked for" fullword
      $g14 = "is blocked" fullword
      $g15 = "potentially harmful"
      $g16 = "Page Blocked" fullword
      $g17 = "page blocked" fullword
   condition:
      extension == ".exe" and not uint16(0) == 0x5a4d and 1 of them
      or (
         extension == ".rar" or 
         extension == ".ps1" or 
         extension == ".vbs" or
         extension == ".bat"
      )
      and 1 of ($x*)
}