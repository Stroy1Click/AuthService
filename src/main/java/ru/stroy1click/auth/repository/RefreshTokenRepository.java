package ru.stroy1click.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import ru.stroy1click.auth.entity.RefreshToken;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {

    Optional<RefreshToken> findFirstByToken(String token);

    @Query(value = """
                SELECT * FROM auth.refresh_tokens
                WHERE expiry_date < NOW()
                LIMIT 100
                FOR UPDATE SKIP LOCKED
                """,
            nativeQuery = true)
    List<RefreshToken> findAllExpiredTokens();

    void deleteByToken(String token);

    Integer countByUserEmail(String userEmail);

    void deleteAllByUserEmail(String userEmail);
}