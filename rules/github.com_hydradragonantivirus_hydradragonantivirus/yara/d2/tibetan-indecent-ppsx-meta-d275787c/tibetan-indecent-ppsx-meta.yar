rule tibetan_indecent_ppsx_meta {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $createdby  = "<dc:creator>Windows User</dc:creator>"
    $createdate = "<dcterms:created xsi:type=\"dcterms:W3CDTF\">2017-10-23T00:57:05Z</dcterms:created>"

  condition:
    all of them
}