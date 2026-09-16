rule TTP_XOR_WriteProcessMemory_9edf {
  strings:
    $key_9edf = { c9 ad [2] fb 8f [2] fd ba [2] d3 ba [2] ec a6 }

  condition:
    any of them
}