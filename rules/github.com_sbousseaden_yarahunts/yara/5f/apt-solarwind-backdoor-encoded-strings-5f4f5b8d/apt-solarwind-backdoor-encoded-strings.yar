rule APT_Solarwind_Backdoor_Encoded_Strings {
meta: 
 author = "SBousseaden"
 description = "This rule is looking for some key encoded strings of the SUNBURST backdoor"
 md5 = "846E27A652A5E1BFBD0DDD38A16DC865"
 sha2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
 date = "14/12/2020"
 reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
strings:
 $sw = "SolarWinds"
 $priv1 = "C04NScxO9S/PSy0qzsgsCCjKLMvMSU1PBQA=" wide  $priv2 = "C04NzigtSckvzwsoyizLzElNTwUA" wide  $priv3 = "C04NSi0uyS9KDSjKLMvMSU1PBQA=" wide $disc1 = "C0gsSs0rCSjKT04tLvZ0AQA=" wide  $disc2 = "c0zJzczLLC4pSizJLwIA" wide  $disc3 = "c/ELdsnPTczMCy5NS8usCE5NLErO8C9KSS0CAA==" wide  $wmi1 = "C07NSU0uUdBScCvKz1UIz8wzNooPriwuSc11KcosSy0CAA==" wide  $wmi2 = "C07NSU0uUdBScCvKz1UIz8wzNooPKMpPTi0uBgA=" wide  $wmi3 = "C07NSU0uUdBScCvKz1UIz8wzNooPLU4tckxOzi/NKwEA" wide  $wmi4 = "C07NSU0uUdBScCvKz1UIz8wzNor3Sy0pzy/KdkxJLChJLXLOz0vLTC8tSizJzM9TKM9ILUpV8AxwzUtMyklNsS0pKk0FAA=="  $key1 = "C44MDnH1jXEuLSpKzStxzs8rKcrPCU4tiSlOLSrLTE4tBgA=" wide $key2 = "Cy5JLCoBAA==" wide  $pat1 = "i6420DGtjVWoNqzlAgA=" wide  $pat2 = "i6420DGtjVWoNtTRNTSrVag2quWsNgYKKVSb1MZUm9ZyAQA=" wide  $pat3 = "qzaoVag2rFXwCAkJ0K82quUCAA==" wide  $pat4 = {9D 2A 9A F3 27 D6 F8 EF}
condition: uint16(0) == 0x5a4d and $sw and (2 of ($pat*) or 2 of ($priv*) or all of ($disc*) or 2 of ($wmi*) or all of ($key*))
}