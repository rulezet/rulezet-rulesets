rule TTP_XOR_WriteProcessMemory_acca {
  strings:
    $key_acca = { fb b8 [2] c9 9a [2] cf af [2] e1 af [2] de b3 }

  condition:
    any of them
}