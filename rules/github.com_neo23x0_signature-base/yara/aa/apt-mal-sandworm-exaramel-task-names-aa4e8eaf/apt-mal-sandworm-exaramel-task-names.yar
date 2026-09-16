rule APT_MAL_Sandworm_Exaramel_Task_Names {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects names of the tasks received from the CC server in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "185f2f3b-bf5c-54af-bca2-400d08bf9c91"
   strings:
      $ = "App.Delete"
      $ = "App.SetServer"
      $ = "App.SetProxy"
      $ = "App.SetTimeout"
      $ = "App.Update"
      $ = "IO.ReadFile"
      $ = "IO.WriteFile"
      $ = "OS.ShellExecute"
   condition:
      all of them
}