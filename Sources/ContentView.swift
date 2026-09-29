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
                    Text("SONDEO DE CLAVES")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .background(reader.busy ? Color.gray : Color.orange)
                .foregroundColor(.white)
                .cornerRadius(10)
                .disabled(reader.busy)
                .alert("¿Sondear las claves?", isPresented: $showAuthConfirm) {
                    Button("Cancelar", role: .cancel) { }
                    Button("Sondear", role: .destructive) { reader.startDefaultKeyProbe() }
                } message: {
                    Text("Fase 1, sin riesgo: GetKeySettings y GetKeyVersion. Solo preguntan al chip qué tipo de clave usa y en qué versión está cada una. No autentican, no gastan intentos.\n\nFase 2, solo si la fase 1 lo justifica: probar la clave 00…00 UNA vez por clave, y solo en las que parezcan de fábrica. Cada clave tolera 3 fallos, así que como mucho gasta 1 de 3.\n\nNunca se escribe, ni se borra, ni se formatea nada.")
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

                Text("LEER TARJETA explora sin autenticar nada. SONDEO DE CLAVES primero pregunta (GetKeySettings, GetKeyVersion) y solo prueba la clave por defecto una vez por clave si la información lo justifica. Ninguna de las dos escribe.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding()
            .navigationTitle("NFC DESFire")
        }
        .navigationViewStyle(.stack)
    }
}
