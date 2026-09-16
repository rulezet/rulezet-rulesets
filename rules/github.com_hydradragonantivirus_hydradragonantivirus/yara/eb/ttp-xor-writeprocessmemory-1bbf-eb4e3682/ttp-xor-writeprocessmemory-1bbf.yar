rule TTP_XOR_WriteProcessMemory_1bbf {
  strings:
    $key_1bbf = { 4c cd [2] 7e ef [2] 78 da [2] 56 da [2] 69 c6 }

  condition:
    any of them
}