rule TTP_XOR_WriteProcessMemory_34bf {
  strings:
    $key_34bf = { 63 cd [2] 51 ef [2] 57 da [2] 79 da [2] 46 c6 }

  condition:
    any of them
}