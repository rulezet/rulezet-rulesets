rule SUSP_JS_NPM_SetupScript_Nov25 {
   meta:
      description = "Detects suspicious JavaScript which exits silently and checks operating system"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
      score = 70
   strings:
      $s1 = "require('child_process')"
      $s2 = "process.exit(0)"
      $s3 = "process.platform ==="
      $s4 = "().catch((e"
   condition:
      filesize < 100KB
      and all of them
}