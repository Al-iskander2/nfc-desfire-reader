import SwiftUI
import UIKit

struct ContentView: View {
    @ObservedObject var reader: DesfireReader

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 14) {

                VStack(alignment: .leading, spacing: 6) {
                    Text("Servidor FastAPI (Mac)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextField("http://IP_DEL_MAC:8000/scan", text: $reader.serverURL)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .keyboardType(.URL)
                        .font(.system(.footnote, design: .monospaced))
                }

                Button(action: { reader.start() }) {
                    HStack {
                        if reader.busy { ProgressView().padding(.trailing, 4) }
                        Text(reader.busy ? "Leyendo..." : "LEER TARJETA")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                }
                .background(reader.busy ? Color.gray : Color.accentColor)
                .foregroundColor(.white)
                .cornerRadius(10)
                .disabled(reader.busy)

                Text(reader.status)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if !reader.output.isEmpty {
                    HStack {
                        Text("Resultado")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button("Copiar") {
                            UIPasteboard.general.string = reader.output
                        }
                        .font(.caption)
                    }
                    ScrollView {
                        Text(reader.output)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                }

                Spacer(minLength: 0)

                Text("Solo lectura: GetVersion, GetApplicationIDs, SelectApplication, GetFileIDs, GetFileSettings, ReadData. No autentica ni escribe nada.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding()
            .navigationTitle("NFC DESFire")
        }
        .navigationViewStyle(.stack)
    }
}
