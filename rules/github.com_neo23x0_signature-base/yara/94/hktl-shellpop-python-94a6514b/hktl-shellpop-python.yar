rule HKTL_shellpop_Python {
   meta:
      description = "Detects malicious python shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"
      id = "62fe0ae9-422e-5021-8a67-e88ff4bd2cf3"
   strings:
      $ = "os.putenv('HISTFILE', '/dev/null');" ascii
   condition:
      filesize < 2KB and 1 of them
}