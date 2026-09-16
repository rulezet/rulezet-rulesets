rule SUSP_ScreenConnect_User_2024_No_Logon_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user created in 2024 but without any login, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
      date = "2024-02-23"
      score = 60
      id = "c0861f1c-08e2-565d-a468-2075c51b4004"
   strings:
      $a1 = "<Users xmlns:xsi="
      $a2 = "<CreationDate>"

      $s1 = "<CreationDate>2024-"
      $s2 = "<LastLoginDate>0001-01-01T00:00:00</LastLoginDate>"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}