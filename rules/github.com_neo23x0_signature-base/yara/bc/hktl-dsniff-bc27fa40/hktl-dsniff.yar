rule HKTL_Dsniff {
   meta:
      description = "Detects Dsniff hack tool"
      author = "Florian Roth (Nextron Systems)"
      score = 55
      reference = "https://goo.gl/eFoP4A"
      date = "2019-02-19"
      id = "eb39185b-330f-5b93-ac58-0465e5767919"
   strings:
      $x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*"
   condition:
      1 of them
}