




void OnInvoke()
{
    int cmd;
    switch (cmd)
    {
        case OPEN_SESSION:

        TA_OpenSessionEntryPoint();


        case CLOSE_SESSION:
        TA_CloseSessionEntryPoint();


    }
}