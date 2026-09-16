rule TTP_XOR_WriteProcessMemory_14bf {
  strings:
    $key_14bf = { 43 cd [2] 71 ef [2] 77 da [2] 59 da [2] 66 c6 }

  condition:
    any of them
}