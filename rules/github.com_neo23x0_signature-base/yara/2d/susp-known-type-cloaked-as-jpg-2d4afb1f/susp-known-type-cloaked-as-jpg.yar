rule SUSP_Known_Type_Cloaked_as_JPG {
   meta:
      description = "Detects a non-JPEG file type cloaked as .jpg"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - replacement for Cloaked_as_JPG rule"
      date = "2022-09-16"
      score = 60
      id = "728908a6-74cf-5bab-a23f-cd03ed209430"
   condition:
      (extension == ".jpg" or extension == ".jpeg") and (
         filetype == "EXE" or
         filetype == "ELF" or
         filetype == "MACH-O" or
         filetype == "VBS" or
         filetype == "PHP" or
         filetype == "JSP" or
         filetype == "Python" or
         filetype == "LSASS Dump File" or
         filetype == "ASP" or
         filetype == "BATCH" or
         filetype == "RTF" or
         filetype == "MDMP" or

         filetype contains "PowerShell" or
         filetype contains "Base64"
      )
}