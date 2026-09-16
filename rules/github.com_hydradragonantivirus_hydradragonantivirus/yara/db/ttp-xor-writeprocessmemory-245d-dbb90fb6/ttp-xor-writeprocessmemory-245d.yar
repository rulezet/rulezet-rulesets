rule TTP_XOR_WriteProcessMemory_245d {
  strings:
    $key_245d = { 73 2f [2] 41 0d [2] 47 38 [2] 69 38 [2] 56 24 }

  condition:
    any of them
}