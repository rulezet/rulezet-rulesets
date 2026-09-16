rule TTP_XOR_WriteProcessMemory_b8bf {
  strings:
    $key_b8bf = { ef cd [2] dd ef [2] db da [2] f5 da [2] ca c6 }

  condition:
    any of them
}