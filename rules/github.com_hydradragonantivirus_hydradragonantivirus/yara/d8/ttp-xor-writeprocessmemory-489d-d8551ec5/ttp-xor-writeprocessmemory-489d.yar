rule TTP_XOR_WriteProcessMemory_489d {
  strings:
    $key_489d = { 1f ef [2] 2d cd [2] 2b f8 [2] 05 f8 [2] 3a e4 }

  condition:
    any of them
}