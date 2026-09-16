rule TTP_XOR_WriteProcessMemory_05bf {
  strings:
    $key_05bf = { 52 cd [2] 60 ef [2] 66 da [2] 48 da [2] 77 c6 }

  condition:
    any of them
}