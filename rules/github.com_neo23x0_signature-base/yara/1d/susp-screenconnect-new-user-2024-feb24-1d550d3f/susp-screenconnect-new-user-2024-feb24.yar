rule SUSP_ScreenConnect_New_User_2024_Feb24 {
   meta:
      description = "Detects suspicious new ScreenConnect user created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 50
      id = "f6675ded-39a4-590a-a201-fcfe3c056e60"
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}