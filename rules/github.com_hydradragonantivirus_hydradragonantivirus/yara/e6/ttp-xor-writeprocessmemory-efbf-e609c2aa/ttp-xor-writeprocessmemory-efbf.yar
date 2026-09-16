rule TTP_XOR_WriteProcessMemory_efbf {
  strings:
    $key_efbf = { b8 cd [2] 8a ef [2] 8c da [2] a2 da [2] 9d c6 }

  condition:
    any of them
}