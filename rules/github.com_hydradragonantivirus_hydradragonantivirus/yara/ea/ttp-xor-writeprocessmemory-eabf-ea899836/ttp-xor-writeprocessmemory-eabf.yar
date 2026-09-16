rule TTP_XOR_WriteProcessMemory_eabf {
  strings:
    $key_eabf = { bd cd [2] 8f ef [2] 89 da [2] a7 da [2] 98 c6 }

  condition:
    any of them
}