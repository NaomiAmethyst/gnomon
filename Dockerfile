# syntax=docker/dockerfile:1
FROM rust:1.98-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bins

FROM scratch AS runtime
LABEL org.opencontainers.image.title="Gnomon" \
      org.opencontainers.image.description="RFC 10049 Roughtime daemon and client" \
      org.opencontainers.image.source="https://github.com/NaomiAmethyst/gnomon" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.authors="Naomi Persephone Amethyst <naomi@amethyst.name>"
COPY --from=build /build/target/release/gnomon /usr/bin/gnomon
COPY --from=build /build/target/release/gnomond /usr/bin/gnomond
COPY LICENSE /usr/share/licenses/gnomon/LICENSE
COPY README.md NOTICE THIRD-PARTY-NOTICES /usr/share/doc/gnomon/
COPY tests/fixtures/LICENSE-RFC /usr/share/doc/gnomon/LICENSE-RFC
COPY docs/ /usr/share/doc/gnomon/docs/
USER 65532:65532
EXPOSE 5319/udp 5319/tcp
ENTRYPOINT ["/usr/bin/gnomond"]
CMD ["--config", "/etc/gnomon/gnomon.toml"]
