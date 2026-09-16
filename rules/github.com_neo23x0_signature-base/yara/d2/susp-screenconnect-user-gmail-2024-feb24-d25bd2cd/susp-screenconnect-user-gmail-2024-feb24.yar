rule SUSP_ScreenConnect_User_Gmail_2024_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with Gmail address created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 65
      id = "3c86f4ee-4e8c-566b-b54e-e94418e4ec7e"
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "@gmail.com</Email>"
      $s2 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}