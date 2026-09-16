rule SUSP_JS_NPM_Sha1_Hulud_Nov25 {
   meta:
      description = "Detects suspicious indicators for Sha1 Hulud worm"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
      score = 60
   strings:
      $x1 = "Sha1-Hulud:"
      $x2 = "SHA1HULUD"
   condition:
      filesize < 20MB
      and 1 of them
}