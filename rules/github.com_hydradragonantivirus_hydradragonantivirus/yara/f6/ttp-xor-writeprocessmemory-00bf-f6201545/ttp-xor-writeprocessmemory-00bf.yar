rule TTP_XOR_WriteProcessMemory_00bf {
  strings:
    $key_00bf = { 57 cd [2] 65 ef [2] 63 da [2] 4d da [2] 72 c6 }

  condition:
    any of them
}