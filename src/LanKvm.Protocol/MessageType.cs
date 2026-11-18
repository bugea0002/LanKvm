namespace LanKvm.Protocol;

/// <summary>
/// Wire message identifiers for the TCP control channel.
/// </summary>
public enum MessageType : byte
{
    Hello = 0x01,
    PinChallenge = 0x02,
    PinResponse = 0x03,
    AuthResult = 0x04,
    ScreenInfo = 0x05,

    SwitchScreen = 0x10,
    EdgeReturn = 0x11,

    MouseButton = 0x20,
    MouseWheel = 0x21,
    KeyEvent = 0x22,
    ReleaseAllKeys = 0x23,

    ClipboardText = 0x30,
    ClipboardImage = 0x31,

    Heartbeat = 0x40,
    HeartbeatAck = 0x41,

    UdpMotionFallback = 0x50,

    UpdateRequest = 0x60,
    UpdateChunk = 0x61,
    UpdateComplete = 0x62,
    UpdateError = 0x63,

    ErrorNotice = 0xFF
}

public enum AuthMode : byte
{
    PinPairing = 0,
    DeviceToken = 1
}

/// <summary>
/// Which side of the host screen the client monitor sits on.
/// </summary>
public enum ScreenEdge : byte
{
    Right = 0,
    Left = 1,
    Top = 2,
    Bottom = 3
}

public enum MouseButtonKind : byte
{
    Left = 1,
    Right = 2,
    Middle = 3,
    XButton1 = 4,
    XButton2 = 5
}
