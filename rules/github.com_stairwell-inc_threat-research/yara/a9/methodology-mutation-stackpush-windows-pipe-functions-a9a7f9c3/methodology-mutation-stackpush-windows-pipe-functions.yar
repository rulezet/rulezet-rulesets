rule Methodology_Mutation_StackPush_Windows_Pipe_Functions {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. Here we look for strings from common PE strings, DLLs and functions in type 2 stack strings form, where the string pushed onto the stack 4 bytes at a time using PUSH 0x68, appearing in reverse four byte chunk order, where the PUSH which shows up as an ASCII letter h."
  strings:
    $CallNamedPipe_stackpush = "hehdPiphNamehCall" nocase
    $ConnectNamedPipe_stackpush = "hPipehamedhectNhConn" nocase
    $CreateNamedPipe_stackpush = "hipehmedPhteNahCrea" nocase
    $CreatePipe_stackpush = "hpehtePihCrea" nocase
    $DisconnectNamedPipe_stackpush = "hipehmedPhctNahonnehDisc" nocase
    $GetNamedPipeClientComputerName_stackpush = "hmeherNahmputhntCohCliehPipehamedhGetN" nocase
    $GetNamedPipeClientProcessId_stackpush = "hsIdhoceshntPrhCliehPipehamedhGetN" nocase
    $GetNamedPipeClientSessionId_stackpush = "hnIdhssiohntSehCliehPipehamedhGetN" nocase
    $GetNamedPipeHandleState_stackpush = "hatehleSthHandhPipehamedhGetN" nocase
    $GetNamedPipeInfo_stackpush = "hInfohPipehamedhGetN" nocase
    $GetNamedPipeServerProcessId_stackpush = "hsIdhocesherPrhServhPipehamedhGetN" nocase
    $GetNamedPipeServerSessionId_stackpush = "hnIdhssioherSehServhPipehamedhGetN" nocase
    $PeekNamedPipe_stackpush = "hehdPiphNamehPeek" nocase
    $SetNamedPipeHandleState_stackpush = "hatehleSthHandhPipehamedhSetN" nocase
    $TransactNamedPipe_stackpush = "hehdPiphNamehsacthTran" nocase
    $WaitNamedPipe_stackpush = "hehdPiphNamehWait" nocase
  condition:
    filesize < 15MB and uint16be(0) == 0x4d5a and 1 of them
}