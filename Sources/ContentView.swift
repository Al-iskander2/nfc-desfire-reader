import SwiftUI
import UIKit

struct ContentView: View {
    @ObservedObject var reader: DesfireReader
    @State private var showAuthConfirm = false

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

                Button(action: { showAuthConfirm = true }) {
                    Text("PROBAR CLAVE POR DEFECTO")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .background(reader.busy ? Color.gray : Color.orange)
                .foregroundColor(.white)
                .cornerRadius(10)
                .disabled(reader.busy)
                .alert("¿Probar la clave por defecto?", isPresented: $showAuthConfirm) {
                    Button("Cancelar", role: .cancel) { }
                    Button("Probar", role: .destructive) { reader.startDefaultKeyProbe() }
                } message: {
                    Text("Se prueba la clave 00…00 UNA sola vez por cada clave del chip (0, 3, 4 y 13).\n\nCada clave tolera 3 fallos antes de bloquearse, así que esto gasta 1 de esos 3 en cada una. Si las claves están diversificadas por UID, que es lo habitual en una tarjeta de transporte, fallará.\n\nNo se escribe, ni se borra, ni se formatea nada. Solo lectura.")
                }

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

                Text("LEER TARJETA explora sin autenticar nada. PROBAR CLAVE POR DEFECTO intenta, una sola vez por clave, el valor por defecto. Ninguna de las dos escribe: GetVersion, GetApplicationIDs, SelectApplication, GetFileIDs, GetFileSettings, GetKeySettings, ReadData y Authenticate.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding()
            .navigationTitle("NFC DESFire")
        }
        .navigationViewStyle(.stack)
    }
}
