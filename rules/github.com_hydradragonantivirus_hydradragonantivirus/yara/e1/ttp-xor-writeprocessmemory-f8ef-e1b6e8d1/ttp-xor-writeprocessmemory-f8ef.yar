rule TTP_XOR_WriteProcessMemory_f8ef {
  strings:
    $key_f8ef = { af 9d [2] 9d bf [2] 9b 8a [2] b5 8a [2] 8a 96 }

  condition:
    any of them
}