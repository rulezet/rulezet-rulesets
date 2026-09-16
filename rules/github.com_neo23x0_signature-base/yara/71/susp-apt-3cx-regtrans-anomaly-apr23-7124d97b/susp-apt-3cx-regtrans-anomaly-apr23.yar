rule SUSP_APT_3CX_Regtrans_Anomaly_Apr23 : METARULE {
   meta:
      description = "Detects suspicious .regtrans-ms files with suspicious size or contents"
      author = "Florian Roth"
      reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
      date = "2023-04-12"
      score = 60
      id = "97406b8d-68fe-5f68-a26a-205dd4694e50"
   strings:
      $fp1 = "REGISTRY" wide
   condition:
      extension == ".regtrans-ms" and (
         filesize < 100KB
         and not 1 of ($fp*)
      )
}