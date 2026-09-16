rule TTP_XOR_WriteProcessMemory_c8bf {
  strings:
    $key_c8bf = { 9f cd [2] ad ef [2] ab da [2] 85 da [2] ba c6 }

  condition:
    any of them
}