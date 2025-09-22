<h1 align="center">JMD — Java Manipulations Detector</h1>
<p align="center">
    <b>A lightweight CLI tool for detecting Java process <code>JVMTI</code>/<code>JNI</code> injections on Windows</b><br>
    <i>This is an improved version of a cool program: <a href="https://github.com/NotRequiem/InjGen">InjGen</a></i>
</p>

### Tested Clients
- Lunar Client (all versions)
- LabyMod (all versions)
- Fabric (all versions)
- Forge (1.8.9 - 1.21.8)
- Vanilla (1.8.9 - 1.21.8)

### Quick Start:
```bash
curl -OL "https://github.com/danfordd/jmd-windows/releases/download/main/jmd.exe" && jmd.exe && del jmd.exe
```

### Notes
1. Badlion Client will flag JMD due to them performing JNI injections.  
2. JNI and JVMTI injections are not the only injection methods.  
   If a client injects using the Forge API(Vape Lite can do it), it won't be detected — because Forge does not modify JVM memory directly.
3. Some other hacked clients like Entropy, Dream or Drip may be aswell detected if they perform blatant modifications to the JVM
