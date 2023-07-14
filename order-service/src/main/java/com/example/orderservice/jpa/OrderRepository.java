package com.example.orderservice.jpa;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<OrderEntity, Long> {
    OrderEntity findByOrderId(String OrderId);
    Iterable<OrderEntity> findByUserId(String userId);
}
