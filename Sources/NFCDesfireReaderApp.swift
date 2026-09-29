import SwiftUI

@main
struct NFCDesfireReaderApp: App {
    @StateObject private var reader = DesfireReader()

    var body: some Scene {
        WindowGroup {
            ContentView(reader: reader)
        }
    }
}
