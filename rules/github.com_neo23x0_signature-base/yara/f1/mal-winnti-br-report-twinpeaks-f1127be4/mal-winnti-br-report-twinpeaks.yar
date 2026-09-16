rule MAL_Winnti_BR_Report_TwinPeaks {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "2e4e2b88-fdb4-5adc-8192-a304d71ca851"
   strings:
      $cooper = "Cooper"
      $pattern = { e9 ea eb ec ed ee ef f0}
   condition:
      uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}