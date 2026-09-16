rule TTP_XOR_WriteProcessMemory_241b {
  strings:
    $key_241b = { 73 69 [2] 41 4b [2] 47 7e [2] 69 7e [2] 56 62 }

  condition:
    any of them
}