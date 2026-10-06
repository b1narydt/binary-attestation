FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p binary-attestation-dstack --features producer --example live_probe

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home probe
COPY --from=builder /src/target/release/examples/live_probe /usr/local/bin/bcap1-live-probe
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/bcap1-live-probe"]
