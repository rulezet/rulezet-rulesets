rule TTP_XOR_WriteProcessMemory_9ef3 {
  strings:
    $key_9ef3 = { c9 81 [2] fb a3 [2] fd 96 [2] d3 96 [2] ec 8a }

  condition:
    any of them
}