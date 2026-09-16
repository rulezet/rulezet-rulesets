rule TTP_XOR_WriteProcessMemory_cfc7 {
  strings:
    $key_cfc7 = { 98 b5 [2] aa 97 [2] ac a2 [2] 82 a2 [2] bd be }

  condition:
    any of them
}