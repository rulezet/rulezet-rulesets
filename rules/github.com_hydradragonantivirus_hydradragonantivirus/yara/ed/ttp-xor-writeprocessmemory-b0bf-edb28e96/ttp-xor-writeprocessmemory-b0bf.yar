rule TTP_XOR_WriteProcessMemory_b0bf {
  strings:
    $key_b0bf = { e7 cd [2] d5 ef [2] d3 da [2] fd da [2] c2 c6 }

  condition:
    any of them
}