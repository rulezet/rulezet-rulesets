rule TTP_XOR_WriteProcessMemory_feaf {
  strings:
    $key_feaf = { a9 dd [2] 9b ff [2] 9d ca [2] b3 ca [2] 8c d6 }

  condition:
    any of them
}